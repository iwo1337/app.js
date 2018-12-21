'use strict';

const Imap = require('imap');
const fs = require('fs');
const request = require('request');
const express = require('express');
const http = require('http');
const socketio = require('socket.io');
const SteamUser = require('steam-user');
const sqlite3 = require('sqlite3');

const app = express();
const server = http.Server(app)
const io = socketio(server);

const settings = JSON.parse(fs.readFileSync('./app-files/config.json', 'utf-8'));

const imap = new Imap({
    user: settings.email.inbox,
    password: settings.email.password,
    host: settings.email.host,
    port: settings.email.port,
	secure: settings.email.secure,
    tls: settings.email.tls
});

const db = new sqlite3.Database('./app-files/steam-creator.db', sqlite3.OPEN_READWRITE, (err) => {
    if (err) handleError(err);
    log('DB connected', 2)
    if (settings.database.cleanup_on_start) {
        let sql = 'DELETE FROM accounts WHERE email IS NOT NULL AND steamid IS NULL';
        db.run(sql, (err) => {
            if (err) handleError(err);
            log('Cleaned DB', 1);
        });
    }
});

const port = process.argv[3] ? process.argv[3] : 80;
const mode = ['fast', 'auto'].includes(process.argv[2]) ? process.argv[2] : 'normal';
const autoConcurrency = process.argv[3] ? process.argv[3] : 1;

const logLevel = 1; // 0: ERROR (only errors) | 1: INFO (only finished actions) | 2: DEBUG (all)

let imapChangeable = true;
let emailTryCount = [];
let queueSize;
let currentProxy;
let proxyByGid = [];
let proxyFails = [];
let proxySwitching = false;

fs.writeFile('./app-files/info.log', '', 'utf-8', (err) => {
    if (err) throw (err);
    start();
});

app.use(express.static('files', {
    etag: true
}));

app.get('/', function (req, res) {
    res.sendFile(__dirname + '/public/index.html');
});

imap.on('ready', () => {
    io.emit('status', {
        imap: imap.state
    });
    checkBoxStatus();
    imapChangeable = true;
});

imap.on('error', (err) => {
    log('IMAP: ' + err, 2);
    if (mode == 'auto') {
        imapConnect();
    }
    io.emit('status', {
        imap: imap.state
    });
});

imap.on('end', function () {
    io.emit('status', {
        imap: imap.state
    });
    imapChangeable = true;
});

io.on('connection', (socket) => {
    socket.on('captcha', (data) => {
        if (data.action == 'request')
            startAccountCreation(socket);
        else if (data.action == 'send')
            verifyCaptcha(data.gid, data.captcha, socket);
    });
    socket.on('status', () => {
        socket.emit('status', {
            imap: imap.state
        });
    });
    socket.on('imap', (connect) => {
        if (imapChangeable) {
            if (connect)
                imapConnect();
            else {
                imap.end();
            }
        }
    });
});

function start() {
    if (mode == 'auto') {
        imapConnect();
        queueSize = autoConcurrency;
    } else {
        server.listen(port, () => {
            log('running on port ' + port, 1);
        });
    }
    if (settings.proxy.enabled)
        getProxy(false);
    else if (mode == 'auto')
        start();
}

function runQueue() {
    if (queueSize != 0) {
        let size = queueSize;
        queueSize = 0;
        log('Starting tasks: ' + size, 1);
        for (let i = size; i > 0; i--) {
            setTimeout(() => {
                log('Started task #' + i, 1);
                startAccountCreation(0);
            }, 1000 * i);
        }
    }
}

function startAccountCreation(socket) {
    if (proxySwitching && !socket) {
        queueSize++;
        return;
    }
    let proxy = currentProxy;
    request.post('https://store.steampowered.com/join/refreshcaptcha/', {
        proxy: proxy
    }, (err, res, body) => {
        if (err) {
            log(err, 2);
            switchProxy(proxy);
        } else if (res && body) {
            try {
                body = JSON.parse(body);
                let gid = body.gid;
                request.get('https://store.steampowered.com/login/rendercaptcha?gid=' + gid, {
                    encoding: null,
                    proxy: proxy
                }, (err, res, body) => {
                    if (err) {
                        log(err, 2);
                        switchProxy(proxy);
                    } else if (res && body) {
                        proxyByGid[gid] = proxy;
                        let base64 = new Buffer.from(body).toString('base64');
                        if (socket) {
                            socket.emit('captcha', {
                                btn: {
                                    send: true,
                                    captcha: true
                                },
                                gid: gid,
                                base64: base64,
                                message: {
                                    text: 'Captcha loaded',
                                    icon: 2
                                }
                            });
                        } else {
                            solveCaptcha(gid, base64);
                        }
                    } else {
                        log('Captcha loading error (2), retrying', 1);
                        startAccountCreation(socket);
                        if (socket) {
                            socket.emit('captcha', {
                                load_new: true,
                                btn: {
                                    captcha: false,
                                    send: false
                                },
                                message: {
                                    text: 'Captcha loding error, retrying',
                                    icon: 3
                                }
                            });
                        }
                    }
                });
            } catch (e) {
                log(e);
                if (!socket)
                    startAccountCreation(null);
            }
        } else {
            log('Captcha loading error (1), retrying', 1);
            startAccountCreation(socket);
            if (socket) {
                socket.emit('captcha', {
                    load_new: true,
                    btn: {
                        captcha: false,
                        send: false
                    },
                    message: {
                        text: 'Captcha loding error, retrying',
                        icon: 3
                    }
                });
            }
        }
    });
}

function solveCaptcha(gid, base64) {
    request.post('https://2captcha.com/in.php', {
        form: {
            key: settings.captcha.apikey,
            method: 'base64',
            min_len: 6,
            max_len: 6,
            language: 2,
            body: base64,
            json: 1
        }
    }, (err, res, body) => {
        if (err) handleError(err);
        body = JSON.parse(body);
        if (body.status == 1) {
            setTimeout(() => {
                check2captcha(gid, body.request)
            }, 5000);
        } else if (JSON.stringify(body) == 'ERROR_NO_SLOT_AVAILABLE') {
            log('2captcha busy, retrying');
            setTimeout(() => {
                solveCaptcha(gid, base64);
            });
        } else if (JSON.stringify(body) == 'ERROR_IMAGE_TYPE_NOT_SUPPORTED') {
            startAccountCreation(socket);
        } else {
            handleError(JSON.stringify(body));
        }
    });
}

function check2captcha(gid, id) {
    let url = 'https://2captcha.com/res.php?key=' + settings.captcha.apikey + '&action=get&soft_id=2355&json=1&id=' + id;
    request.get(url, (err, res, body) => {
        if (err) handleError(err);
        else if (res && body) {
            body = JSON.parse(body);
            if (body.status == 1) {
                let captcha = body.request;
                captcha = captcha.replace(/amp;/g, '');
                log('Captcha solved: ' + captcha, 2);
                verifyCaptcha(gid, captcha, null, id);
            } else if (body.request == 'CAPCHA_NOT_READY') {
                log('Catpcha waiting...', 2)
                setTimeout(() => {
                    check2captcha(gid, id)
                }, 5000);
            } else if (body.request == 'ERROR_CAPTCHA_UNSOLVABLE') {
                log('Captcha unsolvable', 2);
                startAccountCreation(null);
            } else {
                handleError('2captcha: ' + id + ' >' + JSON.stringify(body));
            }
        } else {
            setTimeout(() => {
                check2captcha(gid, id)
            }, 5000);
        }
    });
}

function verifyCaptcha(gid, captcha, socket, id2captcha) {
    let proxy = proxyByGid[gid];
    request.post('https://store.steampowered.com/join/verifycaptcha/', {
        form: {
            captchagid: gid,
            captcha_text: captcha,
        },
        proxy: proxy
    }, (err, res, body) => {
        if (err) {
            log(err, 2);
            switchProxy(proxy);
        } else if (res && body) {
            body = JSON.parse(body);
            if (body.bCaptchaMatches && body.bEmailAvail) {
                getEmailAddress(gid, captcha, socket, proxy);
                if (mode == 'normal') {
                    socket.emit('captcha', {
                        message: {
                            text: 'Captcha verified, creating account',
                            icon: 1
                        }
                    });
                }
                log('Captcha verified, creating account', 2);
            } else if (!body.bCaptchaMatches && body.bEmailAvail) {
                log('Captcha don\'t match', 2);
                if (mode == 'normal') {
                    socket.emit('captcha', {
                        load_new: true,
                        btn: {
                            captcha: true,
                            send: true
                        },
                        message: {
                            text: 'Captcha don\'t match',
                            icon: 3
                        }
                    });
                } else if (!socket) {
                    badCaptcha(id2captcha);
                    log('Reporting bad captcha: ' + captcha + ' (id: ' + id2captcha + ')', 2);
                    startAccountCreation(null);
                }
            }
        } else {
            handleError('Unexpected captcha verification error');
        }
    });
}

function getEmailAddress(gid, captcha, socket, proxy) {
    let sql = 'SELECT username from accounts where created = 0 AND email IS NULL LIMIT 1';
    db.all(sql, (err, rows) => {
        if (err) handleError(err);
        if (rows.length != 1) {
            if (socket) {
                socket.emit('captcha', {
                    btn: {
                        captcha: true,
                        send: true
                    },
                    message: {
                        text: 'No more usernames in the DB',
                        icon: 3
                    }
                });
            }
            handleError('No more usernames in the DB');
        } else {
            let username = rows[0].username;
            let email = username + '@' + settings.email.domain;
            verifyEmail(email, username, gid, captcha, socket, proxy);
        }
    });
}

function verifyEmail(email, username, gid, captcha, socket, proxy) {
    new Promise((resolve, reject) => {
        let sql = 'UPDATE accounts SET email = ? WHERE username = ?';
        db.run(sql, [email, username], (err) => {
            if (err)
                reject(err);
            else
                resolve();
        });
    }).then(() => {
        if (mode == 'fast') {
            socket.emit('captcha', {
                load_new: true,
                btn: {
                    captcha: true,
                    send: false
                },
                message: {
                    text: 'next one',
                    icon: 2
                }
            });
        }
        request.post('https://store.steampowered.com/join/ajaxverifyemail', {
            form: {
                email: email,
                captchagid: gid,
                captcha_text: captcha
            },
            proxy: proxy
        }, (err, res, body) => {
            if (err) {
                log(err, 2);
                switchProxy(proxy);
            } else if (res && body) {
                body = JSON.parse(body);
                if (body.success == 1) {
                    checkEmailStatus(email, username, body.sessionid, socket, proxy);
                    if (mode == 'normal') {
                        socket.emit('captcha', {
                            btn: {
                                captcha: true,
                                send: true
                            },
                            message: {
                                text: 'Waiting for the email',
                                icon: 1
                            }
                        });
                    }
                    log('Waiting for the email ' + email, 2);
                } else if (body.success == 84) {
                    log('IP blocked (timeout)', 1);
                    switchProxy(proxy, false);
                } else {
                    log(JSON.stringify(body));
                    if (!socket)
                        startAccountCreation(null);
                }
            } else {
                handleError('Email verification error');
            }
        });
    }, (err) => {
        handleError(err);
    });
}

function checkEmailStatus(email, username, creationid, socket, proxy) {
    if (!emailTryCount[username])
        emailTryCount[username] = 1;
    else
        emailTryCount[username]++;

    if (emailTryCount[username] > 25) {
        let sql = 'UPDATE accounts SET email = NULL WHERE username = ?';
        db.run(sql, [username], (err) => {
            if (err) handleError(err);
        });
        log(username + ' not verified, skipping', 2);
        if (!socket)
            startAccountCreation(null);
    } else {
        request.post('https://store.steampowered.com/join/ajaxcheckemailverified', {
            form: {
                creationid: creationid
            },
            proxy: proxy
        }, (err, res, body) => {
            if (err) {
                log(err, 2);
                switchProxy(proxy);
            } else if (res && body) {
                if (body == 36) {
                    setTimeout(() => {
                        checkEmailStatus(email, username, creationid, socket);
                    }, 1000);
                } else if (body == 1) {
                    createAccount(username, creationid, socket);
                    if (mode == 'normal') {
                        socket.emit('captcha', {
                            message: {
                                text: 'Email verified, creating account',
                                icon: 1
                            }
                        });
                    }
                    log('Email verified, creating account ' + email, 2);
                } else if (body == 42) {
                    let sql = 'UPDATE accounts SET email = NULL WHERE username = ?';
                    db.run(sql, [username], (err) => {
                        if (err) handleError(err);
                    });
                    switchProxy(proxy);
                } else {
                    setTimeout(() => {
                        checkEmailStatus(email, username, creationid, socket);
                    }, 1000);
                }
            } else {
                setTimeout(() => {
                    checkEmailStatus(email, username, creationid, socket);
                }, 1000);
            }
        });
    }
}

function createAccount(username, creationid, socket) {
    new Promise((resolve, reject) => {
        let password = generateString(8, true);
        let sql = 'UPDATE accounts SET password = ?, created = 1 WHERE username = ?';
        db.run(sql, [password, username], (err) => {
            if (err)
                reject(err);
            else
                resolve(password);
        });
    }, (err) => {
        handleError(err);
    }).then((password) => {
        return new Promise((resolve, reject) => {
            request.post('https://store.steampowered.com/join/createaccount/', {
                form: {
                    accountname: username,
                    password: password,
                    creation_sessionid: creationid
                }
            }, (err, res, body) => {
                if (err) reject(err);
                else if (res && body) {
                    try {
                        body = JSON.parse(body);
                    } catch (e) {
                        log(e);
                        if (!socket)
                            startAccountCreation(null);
                    }
                    if (body.bSuccess) {
                        resolve(password);
                    } else if (body.eresult == 14) {
                        if (socket) {
                            socket.emit('captcha', {
                                btn: {
                                    captcha: false,
                                    send: false
                                },
                                message: {
                                    text: 'Username is not available',
                                    icon: 3
                                }
                            });
                        }
                        log('Username deleted because it is already registered: ' + username, 2);
                        let sql = 'DELETE FROM accounts WHERE username = ?';
                        db.run(sql, [username], (err) => {
                            if (err) handleError(err);
                            else if (mode == 'auto')
                                startAccountCreation(null);
                        });
                    } else {
                        log('Creation failed: ' + JSON.stringify(body), 0);
                        if (mode == 'auto')
                            startAccountCreation(null);
                    }
                } else {
                    reject('Account creation error')
                }
            });
        }, (err) => {
            handleError(err);
        });
    }).then((password) => {
        if (mode == 'normal') {
            socket.emit('captcha', {
                load_new: true,
                btn: {
                    captcha: true,
                    send: false
                },
                message: {
                    text: 'Created ' + username,
                    icon: 2
                }
            });
        }
        log('Created ' + username, 1);
        let sql = 'UPDATE accounts SET created = 1 WHERE username = ?';
        db.run(sql, [username], (err) => {
            if (err) handleError(err);
            getId(username, password);
            if (mode == 'auto')
                startAccountCreation(null);
        })
    });
}

function getId(username, password) {
    let client = new SteamUser();

    client.logOn({
        'accountName': username,
        'password': password
    });

    client.on('loggedOn', () => {
        let sql = 'UPDATE accounts SET steamid = ? WHERE username = ?';
        db.run(sql, [client.steamID.getSteamID64(), username], (err) => {
            if (err) handleError(err);
        });

        if (settings.account.create_login_batch) {
            fs.writeFileSync('./bat/' + username + '.bat', '"C:\\Program Files (x86)\\Steam\\Steam.exe" -login ' + username + ' ' + password);
            fs.appendFileSync('./bat/' + username + '.bat', '\nexit');
        }

        client.requestFreeLicense(settings.account.free_licenses, (err, packages, appids) => {
            if (err) handleError(err);
            log('Added games to ' + username + ': ' + appids + '(' + packages + ')', 2);
            client.gamesPlayed(appids, true);
            let sql = 'UPDATE accounts SET needs_game = 0, game_id = ? WHERE username = ?';
            db.run(sql, [appids.toString(), username], (err) => {
                if (err) handleError(err);
            });
        });
    });

    client.on('accountInfo', (name, country) => {
        let sql = 'UPDATE accounts SET country = ? WHERE username = ?';
        db.run(sql, [country, username], (err) => {
            if (err) handleError(err);
        });
    });

    client.on('webSession', (sessionid, cookies) => {
        request.post('https://store.steampowered.com/twofactor/manage_action', {
            form: {
                action: 'actuallynone',
                sessionid: sessionid
            },
            headers: {
                'Cookie': cookies,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36'
            }
        }, (err, res, body) => {
            if (err) handleError(err);
            let sql = 'UPDATE accounts SET steamguard_disabled = 1 WHERE username = ?';
            db.run(sql, [username], (err) => {
                if (err) handleError;
            });
        });
    });

    setTimeout(() => {
        client.logOff();
    }, 60000);
}

function generateString(length, need_num = false) {
    let str = "";
    let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < length; i++) {
        let x = Math.floor(Math.random() * chars.length);
        str += chars.charAt(x);
    }
    if ((need_num && !str.match(/\d/)) || !(str.match(/[A-Z]/) && str.match(/[a-z]/)))
        return generateString(length, need_num);
    else
        return str;
}

function getMail() {
    imap.openBox('INBOX', false, (err, box) => {
        if (err) handleError(err);
        imap.search(['UNSEEN'], (err, results) => {
            var f = imap.fetch(results, {
                bodies: ['TEXT'],
                markSeen: true
            });
            f.on('message', (msg) => {
                msg.on('body', function (stream) {
                    var buffer = '';
                    stream.on('data', function (chunk) {
                        buffer += chunk.toString('utf8');
                    });
                    stream.once('end', function () {
                        var url = buffer.match(/https:\/\/store.steampowered.com\/account\/newaccountverification([^\n]*)/);
                        if (url)
                            request(url[0]);
                    });
                });
            });
            f.once('error', (err) => {
                log('Fetch error: ' + err), 0;
            });
            f.once('end', () => {
                imap.closeBox((err) => {
                    if (err) handleError(err);
                    checkBoxStatus();
                });
            });
        });
    });
}

function checkBoxStatus() {
    setTimeout(() => {
        imap.status('INBOX', (err, box) => {
            if (err) handleError(err);
            if (box.messages.unseen > 0)
                getMail();
            else
                checkBoxStatus();
        });
    }, 500);
}

function imapConnect() {
    if (imapChangeable) {
        imapChangeable = false;
        imap.connect();
    }
}

function badCaptcha(id) {
    let url = 'https://2captcha.com/res.php?key=' + settings.captcha.apikey + '&action=reportbad&json=1&id=' + id;
    request.get(url, (err, res, body) => {
        if (err) handleError(err);
        body = JSON.parse(body);
        if (body.request == 'OK_REPORT_RECORDED') {
            log('Captcha reported', 2);
        } else {
            handleError('2captcha: ' + JSON.stringify(body));
        }
    });
}

function switchProxy(proxy, force) {
    if (settings.proxy.enabled) {
        if (proxy == currentProxy) {
            if (proxyFails[proxy])
                proxyFails[proxy]++;
            else
                proxyFails[proxy] = 1;

            if (proxyFails[proxy] > settings.proxy.threshold && !proxySwitching || force) {
                log('Proxy switch requested, switching now', 1);
                getProxy(true);
            } else if (proxySwitching) {
                log('Proxy switch requested, in progress', 2);
                queueSize++;
            } else {
                log('Proxy switch requested, ' + proxyFails[proxy] + '/' + settings.proxy.threshold + ' failed attempts', 2);
                startAccountCreation(null);
            }
        } else {
            log('Proxy switch requested, already switched', 2);
            startAccountCreation(null);
        }
    } else {
        handleError('Connection error');
    }
}

function getProxy(addQueue = false, force = false) {
    if (addQueue)
        queueSize++;

    if (!proxySwitching || force) {
        proxySwitching = true;
        let url;
        if (settings.proxy.getproxylist.apikey != "")
            url = 'https://api.getproxylist.com/proxy?allowsPost=1&protocol[]=http&allowsHttps=1&allowsUserAgentHeader=1&apiKey=' + settings.proxy.getproxylist.apikey;
        else
            url = 'https://api.getproxylist.com/proxy?allowsPost=1&protocol[]=http&allowsHttps=1&allowsUserAgentHeader=1';

        request.get(url, (err, res, body) => {
            if (err) handleError(err);
            body = JSON.parse(body);
            if (!body.ip) {
                handleError('proxy: ' + body.error);
            }
            let newProxy = 'http://' + body.ip + ':' + body.port;
            log('Testing new proxy: ' + newProxy, 2);
            request.post('https://store.steampowered.com', {
                proxy: newProxy,
                timeout: 3000
            }, (err, res, body) => {
                if (err) {
                    log('Bad proxy', 2);
                    getProxy(false, true);
                } else {
                    if (mode == 'auto')
                        runQueue();
                    log('Got new working proxy: ' + newProxy, 2);
                    currentProxy = newProxy;
                    proxySwitching = false;
                }
            })
        });
    }
}

function handleError(message) {
    let error = new Error(message);
    log(error.stack, 0, true);
}

function log(message, level, kill = false) {
    let date = new Date();
    let datevalues = [
        date.getFullYear(),
        date.getMonth() + 1,
        date.getDate()
    ];
    let timevalues = [
        date.getHours(),
        date.getMinutes(),
        date.getSeconds(),
    ]

    for (let i = 0; i < timevalues.length; i++) {
        if (timevalues[i].toString().length == 1)
            timevalues[i] = '0' + timevalues[i];
    }

    let timeString = datevalues.join('/') + ' ' + timevalues.join(':');

    message = timeString + ': ' + message;

    if (kill)
        console.error(message)
    else
        console.log(message);

    if (level <= logLevel) {
        message = message + '\n';

        fs.appendFile('./app-files/info.log', message, 'utf-8', (err) => {
            if (err) throw (err);
            if (kill)
                process.exit();
        });
    }
}