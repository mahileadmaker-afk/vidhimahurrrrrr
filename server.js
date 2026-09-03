const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const GATE_PASSWORD = process.env.GATE_PASSWORD || 'admin123';
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET_KEY || '';

function generateToken(secret) {
    return crypto.createHash('sha256').update(secret).digest('hex');
}

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { success: false, message: 'Too many login attempts. Try again later.' }
});

app.post('/api/auth', loginLimiter, (req, res) => {
    const { password } = req.body;
    if (password === GATE_PASSWORD) {
        return res.json({ success: true, token: generateToken(GATE_PASSWORD) });
    }
    return res.status(401).json({ success: false, message: 'Incorrect password' });
});

function parseSpintax(text) {
    if (!text) return '';
    return text.replace(/\{([^{}]+)\}/g, (_, choices) => {
        const options = choices.split('|');
        return options[Math.floor(Math.random() * options.length)];
    });
}

function cleanPlainText(html) {
    if (!html) return '';
    return html
        .replace(/<style([\s\S]*?)<\/style>/gi, '')
        .replace(/<script([\s\S]*?)<\/script>/gi, '')
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<\/p>/gi, '\n\n')
        .replace(/<[^>]+>/g, ' ')
        .replace(/[ \t]+/g, ' ')
        .replace(/\n\s*\n/g, '\n\n')
        .trim();
}

// Random delay function to mimic human behavior
function getRandomDelay(minMs = 1500, maxMs = 3500) {
    return Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
}

async function verifyTurnstile(token) {
    if (!TURNSTILE_SECRET || TURNSTILE_SECRET.startsWith('1x00000000')) return true;
    try {
        const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${encodeURIComponent(TURNSTILE_SECRET)}&response=${encodeURIComponent(token)}`
        });
        const data = await response.json();
        return data.success;
    } catch (e) {
        return false;
    }
}

app.post('/api/send-stream', async (req, res) => {
    const { senderName, email, appPassword, subject, body, recipients, cfToken, authToken, unsubscribeUrl } = req.body;

    const expectedToken = generateToken(GATE_PASSWORD);
    if (!authToken || authToken !== expectedToken) {
        return res.status(401).json({ error: 'Unauthorized access' });
    }

    const isHuman = await verifyTurnstile(cfToken);
    if (!isHuman) {
        return res.status(400).json({ error: 'Captcha validation failed' });
    }

    if (!email || !appPassword || !recipients || !Array.isArray(recipients) || recipients.length === 0) {
        return res.status(400).json({ error: 'Missing required mail parameters' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendSSE = (data) => {
        res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    // Nodemailer transporter configuration
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        pool: true,
        maxConnections: 1, // Reduced to avoid IP/Account flagging
        maxMessages: 50,
        auth: {
            user: email,
            pass: appPassword.replace(/\s+/g, '')
        }
    });

    try {
        await transporter.verify();
    } catch (error) {
        sendSSE({ type: 'fatal_error', message: 'SMTP Auth Failed. Verify Email & App Password.' });
        return res.end();
    }

    const total = recipients.length;
    let sentCount = 0;
    let failedCount = 0;

    sendSSE({ type: 'start', total });

    // Reduced batch size to 2 to minimize parallel spam alerts
    const BATCH_SIZE = 2;

    for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
        const batch = recipients.slice(i, i + BATCH_SIZE);

        const batchPromises = batch.map(async (recipient) => {
            const dynamicSubject = parseSpintax(subject);
            const dynamicBody = parseSpintax(body);
            const plainText = cleanPlainText(dynamicBody);
            const domain = email.split('@')[1] || 'gmail.com';

            // Essential headers for anti-spam scoring
            const mailHeaders = {
                'X-Mailer': 'NodeMailer-App',
                'X-Report-Abuse-To': email
            };

            if (unsubscribeUrl) {
                mailHeaders['List-Unsubscribe'] = `<${unsubscribeUrl}>`;
                mailHeaders['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
            }

            const mailOptions = {
                from: `"${senderName}" <${email}>`,
                to: recipient,
                subject: dynamicSubject,
                text: plainText,
                html: dynamicBody,
                headers: mailHeaders,
                messageId: `<${crypto.randomBytes(16).toString('hex')}@${domain}>`,
                date: new Date()
            };

            try {
                await transporter.sendMail(mailOptions);
                return { recipient, success: true };
            } catch (err) {
                return { recipient, success: false, error: err.message };
            }
        });

        const results = await Promise.all(batchPromises);

        results.forEach((resResult) => {
            if (resResult.success) {
                sentCount++;
                sendSSE({ type: 'progress', status: 'sent', recipient: resResult.recipient, sentCount, failedCount });
            } else {
                failedCount++;
                sendSSE({ type: 'progress', status: 'failed', recipient: resResult.recipient, error: resResult.error, sentCount, failedCount });
            }
        });

        // Human-like delay between batches (1.5 to 3.5 seconds)
        if (i + BATCH_SIZE < recipients.length) {
            const delay = getRandomDelay(1500, 3500);
            await new Promise((resolve) => setTimeout(resolve, delay));
        }
    }

    transporter.close();
    sendSSE({ type: 'complete', sentCount, failedCount, total });
    res.end();
});

app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
