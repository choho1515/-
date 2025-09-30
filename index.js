const {
    Client, GatewayIntentBits, Partials, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle,
    SlashCommandBuilder, PermissionsBitField, ChannelType, Events
} = require('discord.js');
const express = require('express');
const axios = require('axios');
const path = require('path');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');
const { GoogleGenAI } = require('@google/genai');
const { QuickDB } = require('quick.db');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const levenshtein = require('js-levenshtein');
const crypto = require('crypto');
const cors = require('cors');
require('dotenv').config();

let marked;
async function loadMarked() {
    if (marked) return marked;
    try {
        const markedModule = await import('marked');
        marked = markedModule.marked;
        return marked;
    } catch (error) {
        console.error('Markdown 모듈 로드 오류:', error);
        return (text) => `Markdown 로드 실패: ${text}`;
    }
}

const ENCRYPTION_KEY_RAW = process.env.EMAIL_ENCRYPTION_KEY;
const ENCRYPTION_KEY = ENCRYPTION_KEY_RAW ? ENCRYPTION_KEY_RAW.trim() : null;
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

if (!ENCRYPTION_KEY || Buffer.byteLength(ENCRYPTION_KEY, 'utf8') !== 32) {
    console.warn("⚠️ EMAIL_ENCRYPTION_KEY가 설정되지 않았거나 길이가 32바이트가 아닙니다.");
}

function encrypt(text) {
    if (!ENCRYPTION_KEY) return text;
    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'utf8'), iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (e) {
        console.error("암호화 실패:", e);
        return 'ENCRYPTION_FAILED:' + text;
    }
}

function decrypt(text) {
    if (!ENCRYPTION_KEY) return text;
    try {
        const textParts = text.split(':');
        if (textParts.length !== 2) return 'DECRYPTION_ERROR:Invalid_Format';
        const iv = Buffer.from(textParts[0], 'hex');
        const encryptedText = Buffer.from(textParts[1], 'hex');
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) {
        return 'DECRYPTION_ERROR:키 불일치 또는 변조됨';
    }
}

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.DirectMessages,
    ],
    partials: [Partials.Channel]
});

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(cors());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/fp', express.static(path.join(__dirname, 'node_modules/@fingerprintjs/fingerprintjs/dist')));

const db = new QuickDB();
const ai = new GoogleGenAI(process.env.GEMINI_API_KEY);
const BACKUP_FILE_PATH = path.join(__dirname, 'config_backup.json');

const transporter = nodemailer.createTransport({
    service: 'naver',
    host: 'smtp.naver.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.NAVER_EMAIL_USER,
        pass: process.env.NAVER_EMAIL_APP_PASSWORD
    }
});

const AUTH_CALLBACK_URI = `${process.env.BASE_URL}/auth/callback`;
const DASHBOARD_CALLBACK_URI = `${process.env.BASE_URL}/dashboard/callback`;

async function exchangeCodeForToken(code, redirectUri) {
    try {
        const response = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: process.env.DISCORD_CLIENT_ID,
            client_secret: process.env.DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri
        }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
        return response.data.access_token;
    } catch (error) {
        console.error("OAuth2 토큰 교환 실패:", error.response?.data || error.message);
        return null;
    }
}

async function destroyUserData(guildId, userId) {
    try {
        const allData = await db.all();
        const promises = [];
        let deletedCount = 0;
        allData.forEach(entry => {
            if (entry.value === userId && (entry.id.startsWith(`email_${guildId}_`) || entry.id.startsWith(`fingerprint_${guildId}_`))) {
                promises.push(db.delete(entry.id));
                deletedCount++;
            }
        });
        promises.push(db.delete(`deletion_schedule_${guildId}_${userId}`));

        const authLogs = await db.get(`auth_logs_${guildId}`) || [];
        const originalLogCount = authLogs.length;

        if (originalLogCount > 0) {
            const updatedLogs = authLogs.filter(log => log.userId !== userId);
            if (updatedLogs.length < originalLogCount) {
                promises.push(db.set(`auth_logs_${guildId}`, updatedLogs));
                deletedCount += (originalLogCount - updatedLogs.length);
            }
        }
        
        await Promise.all(promises);

        console.log(`[DATA DESTROY] 서버 ${guildId}에서 사용자 ${userId}의 관련 기록 ${deletedCount}개를 영구 파기했습니다.`);
        return true;
        
    } catch (error) {
        console.error(`[DATA DESTROY] 사용자 ${userId}의 데이터 파기 중 오류 발생:`, error);
        return false;
    }
}

async function logAuthAttempt(guildId, userId, result, reason, details = {}) {
    try {
        const logEntry = { timestamp: Date.now(), userId, result, reason, ...details };
        await db.push(`auth_logs_${guildId}`, logEntry);
    } catch (error) {
        console.error(`[AUTH LOG] 서버 ${guildId}의 인증 로그 기록 실패:`, error);
    }
}

async function getGeminiAnalysis(userData) {
    const prompt = `
# 페르소나
당신은 온라인 커뮤니티의 악성 사용자를 식별하는 최고의 사이버 보안 분석가입니다.

# 임무
당신은 디스코드 서버 인증을 시도한 사용자의 데이터와 규칙 기반 시스템의 1차 판정 결과를 받게 됩니다. 당신의 임무는 이 모든 정보를 종합하여, 관리자가 상황을 한눈에 파악할 수 있도록 명확하고 간결한 '분석 요약'을 생성하는 것입니다.

# 분석 데이터
${JSON.stringify(userData, null, 2)}

# 분석 지침
1.  판정 결과 확인: \`systemVerdict\`가 'ALLOWED'이면 규칙 기반 인증을 통과한 성공 케이스, 'DENIED'이면 거부된 케이스입니다.
2.  핵심 원인 분석:
    - 'DENIED'인 경우, \`isFingerprintDuplicate\`나 \`isEmailDuplicate\`가 \`true\`일 것입니다. 이것이 차단의 핵심 원인임을 명확히 언급하는 요약을 작성하세요.
    - 'ALLOWED'인 경우에도, 아래의 잠재적 위험 요소를 반드시 확인하여 최종 \`riskLevel\`을 결정해야 합니다.
3.  잠재적 위험 요소 분석 (가장 중요):
    - 유사 이메일 주소 (\`isEmailSimilar\`): \`true\`일 경우, 기존 사용자와 매우 유사한 이메일 주소로 가입한 사용자입니다. 이는 동일인의 다중 계정 시도일 가능성이 높으므로, 위험도를 '높음'으로 판단하고 이 사실을 분석 요약에 반드시 포함하세요.
    - 계정 생성 후 경과 시간 (\`accountAgeInDays\` 필드 확인):
        - 경과 시간이 7일 미만으로 매우 짧음에도 불구하고, 중복 기록이 전혀 없는 깨끗한 상태라면, 이는 잠재적인 악성 계정(Sleeper Account)일 수 있습니다. 위험도를 '의심'으로 판단하세요.
    - 사용자 이름과 이메일의 연관성: 디스코드 사용자 이름(username)이 인증 이메일 주소의 아이디 부분과 거의 동일하거나 매우 유사한 경우, 위험도를 '의심' 수준으로 판단하세요.
    - 의미 없는 사용자 이름: 사용자 이름이 'user' + '숫자' 또는 'test' + '숫자'와 같이 의미 없는 조합일 경우, 위험도를 '보통' 또는 '의심'으로 판단하세요.
4.  종합 판단: 위 규칙들을 종합하여 최종 \`riskLevel\`을 결정하세요. 명백한 중복이 없더라도, 잠재적 위험 요소가 발견되면 위험도 등급을 올리세요. 위험 요소가 없다면 '매우 낮음'으로 판단하세요.

# 출력 형식 (반드시 아래 JSON 형식만 반환할 것. 다른 설명이나 인사말은 절대 포함하지 마세요.)
{
  "riskLevel": "<매우 낮음 | 낮음 | 보통 | 의심 | 높음 | 매우 높음>",
  "reasoning": "<생성된 분석 요약 문장>"
}
`;
    try {
        const response = await ai.models.generateContent({
            model: "gemini-2.5-flash",
            contents: [{ "role": "user", "parts": [{ "text": prompt }] }],
            generationConfig: { responseMimeType: "application/json" },
        });

        let responseText = response.text.trim();
        const jsonStartIndex = responseText.indexOf('{');
        const jsonEndIndex = responseText.lastIndexOf('}');

        if (jsonStartIndex !== -1 && jsonEndIndex !== -1) {
            const jsonString = responseText.substring(jsonStartIndex, jsonEndIndex + 1);
            return JSON.parse(jsonString);
        } else {
            throw new Error("AI 응답에서 유효한 JSON을 찾을 수 없습니다.");
        }

    } catch (error) {
        console.error("Gemini AI 분석 중 오류:", error);
        return { riskLevel: "분석 실패", reasoning: "AI 모델 분석 중 오류가 발생했습니다." };
    }
}
client.once('ready', async () => {
    console.log(`[READY] ${client.user.tag} 준비 완료!`);
    await restoreConfigFromBackup();
    await startDeletionScheduler();
    await startSessionCleaner();
    const setupCommand = new SlashCommandBuilder()
        .setName('설정').setDescription('인증 시스템을 설정합니다.')
        .addChannelOption(option =>
            option.setName('채널')
                .setDescription('인증 메시지를 게시할 텍스트 채널')
                .setRequired(true)
                .addChannelTypes(ChannelType.GuildText))
        .addRoleOption(option =>
            option.setName('역할')
                .setDescription('성공/경고/실패 로그 스레드에서 멘션할 관리자 역할')
                .setRequired(true))
        .setDefaultMemberPermissions(PermissionsBitField.Flags.Administrator);

    const helpCommand = new SlashCommandBuilder()
        .setName('도움말')
        .setDescription('봇의 사용법과 주요 기능에 대한 안내를 표시합니다.');

    await client.application.commands.set([setupCommand, helpCommand]);
});

client.on('interactionCreate', async interaction => {
    if (interaction.isCommand() && interaction.commandName === '도움말') {
        const helpEmbed = new EmbedBuilder()
            .setColor('#5865F2')
            .setTitle('🔒 Verita 봇 도움말')
            .setDescription('안녕하세요! 저는 AI를 이용해 다중 계정을 방지하고 서버 보안을 강화하는 인증 봇입니다.')
            .addFields(
                { name: '👑 관리자용', value: '`/설정` 명령어를 사용하여 인증 안내 메시지를 보낼 채널을 지정해주세요. 웹 대시보드에서는 더 상세한 설정이 가능합니다.' },
                { name: '👤 일반 사용자용', value: '관리자가 지정한 인증 채널에서 **[인증 시작하기]** 버튼을 눌러 인증을 진행할 수 있습니다.' },
                { name: '🌐 추가 정보', value: `[자주 묻는 질문(Q&A)](${process.env.BASE_URL}/QnA) | [개인정보 보호정책](${process.env.BASE_URL}/privacy)` }
            )
            .setFooter({ text: '안전한 서버 환경을 위해 노력합니다.' })
            .setTimestamp();
        await interaction.reply({ embeds: [helpEmbed], ephemeral: true });
    }
    if (interaction.isCommand() && interaction.commandName === '설정') {
        await interaction.deferReply({ ephemeral: true });
        if (!interaction.member.permissions.has(PermissionsBitField.Flags.Administrator)) {
            return interaction.editReply({ content: '🚫 이 명령어를 사용할 권한이 없습니다.' });
        }
        const channel = interaction.options.getChannel('채널');
        try {
            await db.set(`verification_channel_${interaction.guildId}`, channel.id);
            await createLogThreads(channel, interaction.user, interaction.guild.ownerId);
            await postOrUpdateVerificationMessage(channel);
            await saveConfigBackup(interaction.guildId);
            return interaction.editReply({ content: `✅ 이제 ${channel} 채널에서 인증을 시작할 수 있습니다. 설정이 DB와 백업 파일에 모두 저장되었습니다.` });
        } catch (error) {
            console.error("인증 설정 중 오류 발생:", error);
            return interaction.editReply({ content: '❌ 인증 시스템 설정 중 오류가 발생했습니다. 권한 및 설정을 확인해주세요.' });
        }
    }
    if (interaction.isButton() && interaction.customId === 'start_verification') {
        await interaction.deferReply({ ephemeral: true });
        const token = uuidv4();
        await db.set(`session_auth_${token}`, { step: 'start', userId: interaction.user.id, guildId: interaction.guildId, expires: Date.now() + 300000 });
        const baseUrl = process.env.BASE_URL;
        if (!baseUrl) {
            return interaction.editReply({ content: '❌ 서버 설정 오류: BASE_URL 환경 변수가 설정되지 않았습니다.' });
        }
        const authUrl = `${baseUrl}/auth?token=${token}`;
        try {
            await interaction.user.send({ content: `**인증 페이지로 이동합니다.**\n\n아래 링크를 클릭하여 인증을 계속 진행해주세요. 이 링크는 5분간 유효합니다.\n\n> ${authUrl}` });
            return interaction.editReply({ content: '✅ DM으로 인증 링크를 보냈습니다. 확인해주세요!' });
        } catch {
            return interaction.editReply({ content: '❌ DM을 보낼 수 없습니다. 서버의 개인정보 설정을 확인해주세요.' });
        }
    }
    if (interaction.isButton()) {
        const [action, userId] = interaction.customId.split('_');
        if (!['approve-user', 'kick-user', 'investigate-user'].includes(action)) return;
        if (!interaction.member.permissions.has(PermissionsBitField.Flags.Administrator)) {
            return interaction.reply({ content: '🚫 이 버튼을 사용할 권한이 없습니다.', ephemeral: true });
        }
        await interaction.deferReply({ ephemeral: true });
        const member = await interaction.guild.members.fetch(userId).catch(() => null);
        if (!member) {
            return interaction.editReply({ content: '❌ 대상 사용자를 서버에서 찾을 수 없습니다.' });
        }
        if (action === 'approve-user' || action === 'kick-user') {
            const originalMessage = interaction.message;
            const newComponents = originalMessage.components.map(row => {
                const newRow = new ActionRowBuilder();
                row.components.forEach(component => newRow.addComponents(new ButtonBuilder(component.data).setDisabled(true)));
                return newRow;
            });
            await originalMessage.edit({ components: newComponents });
        }
        if (action === 'approve-user') {
            await interaction.editReply({ content: `✅ ${member.user.tag} 님을 승인 처리했습니다.` });
        } else if (action === 'kick-user') {
            try {
                await member.kick('관리자의 경고 확인 후 추방 조치');
                await interaction.editReply({ content: `✅ ${member.user.tag} 님을 서버에서 추방했습니다.` });
            } catch (err) {
                console.error('경고 로그 추방 처리 중 오류:', err);
                await interaction.editReply({ content: `❌ ${member.user.tag} 님을 추방하는 데 실패했습니다. (권한 확인 필요)` });
            }
        } else if (action === 'investigate-user') {
            try {
                const verificationChannelId = await db.get(`verification_channel_${interaction.guildId}`);
                if (!verificationChannelId) return interaction.editReply({ content: '❌ 인증 채널 정보를 DB에서 찾을 수 없어 조사 스레드를 생성할 수 없습니다.' });

                const parentChannel = await interaction.guild.channels.fetch(verificationChannelId);
                if (!parentChannel || !parentChannel.isTextBased()) return interaction.editReply({ content: '❌ 인증 채널이 유효하지 않아 조사 스레드를 생성할 수 없습니다.' });

                const thread = await parentChannel.threads.create({
                    name: `조사: ${member.user.username}`,
                    autoArchiveDuration: 1440,
                    type: ChannelType.PrivateThread,
                    reason: `${member.user.tag}에 대한 관리자 조사`
                });

                await thread.members.add(interaction.user.id);
                await thread.members.add(member.id);

                const dashboardUrl = `${process.env.BASE_URL}/dashboard?guildId=${interaction.guildId}&viewUser=${member.id}`;

                const row = new ActionRowBuilder().addComponents(
                    new ButtonBuilder()
                        .setLabel('대시보드에서 사용자 정보 확인')
                        .setStyle(ButtonStyle.Link)
                        .setURL(dashboardUrl)
                        .setEmoji('📊')
                );

                await thread.send({
                    content: `${interaction.user} 님과 ${member} 님의 개별 조사를 위해 생성된 스레드입니다. 아래 버튼으로 상세 정보를 확인하며 대화를 나눠주세요.`,
                    components: [row]
                });

                await interaction.editReply({ content: `✅ ${member.user.tag} 님과의 개별 조사를 위해 ${thread} 스레드를 생성했습니다.` });

            } catch (err) {
                console.error('조사 스레드 생성 중 오류:', err);
                await interaction.editReply({ content: `❌ 조사 스레드를 생성하는 데 실패했습니다.` });
            }
        }
    }
});
app.use(express.static('public'));
app.get('/', async (req, res) => {
    const markedParse = await loadMarked();
    const whyNeededMarkdown = `
# 서버 인증 시스템의 필요성 및 개인정보 보호 안내
## 1. 악성 사용자 및 어뷰징 방지
대부분의 커뮤니티는 한 사용자가 여러 개의 부계정을 만들어 **규칙을 우회**하거나 **여론을 조작**하는 행위로 인해 피해를 입습니다. 이 시스템은 단순한 캡차가 아닌, **3단계 보안 검증**을 통해 이러한 시도를 사전에 차단합니다.
* **기기 지문 (Fingerprint ID) 확인:** 동일 기기에서 여러 계정으로 인증하는 것을 방지합니다.
* **이메일 중복 확인:** 이미 사용된 이메일 주소의 재사용을 막습니다.
## 2. 개인정보 보호 및 수집 항목 안내
저희 시스템은 사용자님의 **신상 정보(이름, 전화번호, 주소 등)는 일절 수집하지 않습니다.**
> **수집 항목은 오직 두 가지입니다.**
> 1. **인증에 사용된 네이버 이메일 주소 (ID) - 암호화되어 저장됨**
> 2. **사용자 기기의 고유 식별 정보 (Fingerprint ID)**
> 
> 이 정보들은 오직 **다중 계정 생성 및 악성 행위 방지** 목적으로만 이용되며, 외부로 유출되거나 상업적으로 이용되지 않습니다.
## 3. AI 기반 잠재적 위험 분석 (Gemini AI)
중복 기록이 없더라도, 새로운 계정이 위험 요소를 가지고 있는지 심층적으로 분석합니다.
* **유사 이메일 주소 탐지:** 기존 사용자의 이메일 주소와 미묘하게 다른 이메일로 위장하는 행위를 찾아냅니다.
* **신규 계정/잠재적 계정 확인:** 생성된 지 얼마 되지 않은 디스코드 계정은 잠재적인 테러 계정일 수 있습니다. 이를 관리자에게 알립니다.
## 4. 관리자 대응 간소화
인증 결과는 **성공, 경고, 차단** 세 가지 전용 스레드 채널로 자동 분류되어 관리자가 신속하게 대응할 수 있도록 돕습니다.`;
    res.render('home.ejs', {
        title: '환영합니다!',
        contentHtml: markedParse(whyNeededMarkdown)
    });
});
app.get('/QnA', async (req, res) => {
    const parser = await loadMarked();
    const qnaMarkdown = `
# 자주 묻는 질문 (Q&A)
## Q: 왜 네이버 이메일만 사용해야 하나요?
> A: 네이버 이메일은 국내에서 가장 널리 사용되면서도, 임시 이메일이나 일회용 이메일 서비스보다 **본인 확인 절차가 엄격**합니다. 악성 사용자들이 쉽게 버릴 수 있는 해외 임시 메일 사용을 막아 **인증의 신뢰도**를 높이기 위함입니다.
## Q: '기기 지문(Fingerprint ID)'은 무엇이며, 제 개인정보를 수집하나요?
> A: 기기 지문은 사용자의 **IP 주소, 브라우저 설정(해상도, 폰트), 운영체제 정보** 등을 조합하여 생성되는 **고유 식별자**입니다.
<div class="fingerprint-danger-box">
    🚨 <b>주의: 이는 여러분의 이름, 전화번호 등 어떠한 신상 정보도 수집하지 않습니다.</b>
    <br>
    수집 목적은 <b>오직 다중 계정(부계정) 생성을 감지</b>하기 위함이며, 동일 기기에서 여러 계정으로 인증을 시도하는 것을 막는 것이 핵심 기능입니다. 자세한 기술적 내용은 Fingerprintjs의 <a href="https://fingerprint.com/" target="_blank" class="fingerprint-link">공식 홈페이지</a>를 참고해 주십시오.
</div>
## Q: 인증에 실패하고 서버에서 추방당했어요. 왜 그런가요?
> A: 시스템이 **이미 인증에 사용된 이메일 주소**나 **기기 지문 정보**를 감지했을 가능성이 높습니다. 이는 한 사람이 여러 계정을 사용하는 것을 막기 위한 조치입니다. 부계정이 아닌 **본계정으로 인증을 시도**했는지 확인해주세요. 오류라고 판단되면, 관리자에게 문의해주십시오.
`;
    res.render('home.ejs', {
        title: '인증 시스템 Q&A',
        contentHtml: parser(qnaMarkdown)
    });
});
app.get('/tos', async (req, res) => {
    const tosHtml = `
<div style="font-family: sans-serif; line-height: 1.6;">
    <h1 style="font-size: 2em; color: #5865F2; margin-bottom: 0.5em;">서비스 약관 (Terms of Service)</h1>
    <h2 style="font-size: 1.5em; margin-top: 1em;">1. 서비스 목적</h2>
    <p>본 봇(Verita)은 Discord 서버 내에서 <strong>다중 계정 생성 및 악성 사용자 활동을 방지</strong>하여 안전하고 공정한 커뮤니티 환경을 유지하는 것을 유일한 목적으로 합니다.</p>
    <h2 style="font-size: 1.5em; margin-top: 1em;">2. 동의</h2>
    <p>본 봇의 인증 시스템을 사용하는 것은 본 약관에 동의하는 것으로 간주됩니다. 사용자는 반드시 Discord 이용약관 및 커뮤니티 가이드라인을 준수해야 합니다.</p>
    <h2 style="font-size: 1.5em; margin-top: 1em;">3. 금지 행위</h2>
    <p>봇의 기능을 악용하여 인증 시스템을 우회하거나, 비정상적인 방법으로 서버에 침입하려는 모든 시도는 금지되며, 이 경우 즉시 영구적인 차단 조치가 이루어질 수 있습니다.</p>
    <h2 style="font-size: 1.5em; margin-top: 1em;">4. 책임의 제한</h2>
    <p>본 봇은 서버 관리자의 재량으로 운영되며, 봇 사용으로 인해 발생하는 간접적, 부수적, 징벌적 손해에 대해 어떠한 책임도 지지 않습니다.</p>
    <h2 style="font-size: 1.5em; margin-top: 1em;">5. 서비스 중단</h2>
    <p>Discord 정책 변경, 기술적 문제 또는 서버 운영 종료 등의 사유로 서비스가 예고 없이 일시적 또는 영구적으로 중단될 수 있습니다.</p>
    <h2 style="font-size: 1.5em; margin-top: 1em;">6. 약관 변경</h2>
    <p>본 약관은 Discord 정책 및 법률 변경에 따라 사전 고지 없이 변경될 수 있으며, 변경 사항은 본 페이지에 게시 즉시 효력을 발휘합니다.</p>
</div>`;
    res.render('home.ejs', {
        title: '서비스 약관',
        contentHtml: tosHtml
    });
});
app.get('/privacy', async (req, res) => {
    const privacyHtml = `
<div style="font-family: sans-serif; line-height: 1.6;">
    <h1 style="font-size: 2em; color: #5865F2; margin-bottom: 0.5em;">개인정보 보호정책 (Privacy Policy)</h1>

    <h2 style="font-size: 1.5em; margin-top: 1em;">1. 수집 항목 및 목적</h2>
    <p>본 봇은 <strong>다중 계정 및 악성 사용자 방지</strong>라는 목적을 달성하기 위해 다음 정보를 수집합니다. 귀하의 이름, 전화번호, 주소 등 <strong>개인을 직접 식별하는 민감 정보는 일절 수집하지 않습니다.</strong></p>

    <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
        <thead>
            <tr style="background-color: #f3f4f6;">
                <th style="padding: 10px; border: 1px solid #ddd; text-align: left; color: #374151;">수집 항목</th>
                <th style="padding: 10px; border: 1px solid #ddd; text-align: left; color: #374151;">목적</th>
                <th style="padding: 10px; border: 1px solid #ddd; text-align: left; color: #374151;">보유 기간</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;">디스코드 사용자 ID 및 이름</td>
                <td style="padding: 10px; border: 1px solid #ddd;">계정 식별 및 서버 역할 부여</td>
                <td style="padding: 10px; border: 1px solid #ddd;">서비스 이용 기간</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;">네이버 이메일 주소</td>
                <td style="padding: 10px; border: 1px solid #ddd;">본인 확인 및 이메일 중복 방지</td>
                <td style="padding: 10px; border: 1px solid #ddd;">서비스 이용 기간</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;">기기 고유 식별자 (Fingerprint ID)</td>
                <td style="padding: 10px; border: 1px solid #ddd;">기기 중복 확인 및 부정 접속 방지</td>
                <td style="padding: 10px; border: 1px solid #ddd;">서비스 이용 기간</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;">디스코드 계정 생성일</td>
                <td style="padding: 10px; border: 1px solid #ddd;">잠재적 악성 계정 분석</td>
                <td style="padding: 10px; border: 1px solid #ddd;">서비스 이용 기간</td>
            </tr>
        </tbody>
    </table>

    <h2 style="font-size: 1.5em; margin-top: 1em;">2. 데이터 보안 및 암호화</h2>
    <p>수집된 <strong>이메일 주소 및 Fingerprint ID</strong>는 Discord 서버 데이터베이스에 <strong>AES-256 암호화</strong>되어 저장됩니다. 이 데이터는 서버 관리자 외 제3자에게 제공되거나 외부로 유출되지 않도록 엄격하게 관리됩니다.</p>

    <h2 style="font-size: 1.5em; margin-top: 1em;">3. 데이터 보유 및 파기</h2>
    <p>수집된 데이터는 사용자가 서버를 탈퇴하거나 계정 삭제를 요청할 때까지 보유합니다. 삭제 요청 시, 해당 데이터는 DB에서 즉시 영구적으로 파기됩니다.</p>

    <h2 style="font-size: 1.5em; margin-top: 1em;">4. 동의 철회 및 문의</h2>
    <p>개인정보 수집 및 이용에 대한 동의를 철회하거나, 저장된 개인 데이터의 열람, 정정, 삭제를 요청하려면 Discord 내에서 서버 관리자에게 직접 문의하거나 봇의 지원 채널을 이용해 주십시오.</p>
</div>
`;
    res.render('home.ejs', {
        title: '개인정보 보호정책',
        contentHtml: privacyHtml
    });
});
app.delete('/dashboard/data', async (req, res) => {
    const sessionToken = req.cookies.dash_session;
    const session = await db.get(`session_dash_${sessionToken}`);
    if (!session || session.expires < Date.now()) {
        return res.status(401).send({ error: '인증 세션이 만료되었습니다. 다시 로그인해주세요.' });
    }
    const { userId, guildId } = req.body;
    if (!userId || !session.availableGuilds.some(g => g.id === guildId)) {
        return res.status(400).send({ error: '잘못된 요청 또는 권한이 없는 서버입니다.' });
    }
    const success = await destroyUserData(guildId, userId);
    if (success) {
        return res.status(200).send({ message: '데이터가 성공적으로 파기되었습니다.' });
    } else {
        return res.status(500).send({ error: '데이터 파기 처리 중 서버 오류가 발생했습니다.' });
    }
});
app.get('/auth', async (req, res) => {
    const { token } = req.query;
    const session = await db.get(`session_auth_${token}`);
    if (!session || session.expires < Date.now()) {
        return res.render('auth.ejs', { stage: 'error', error: '인증 링크가 만료되었거나 유효하지 않습니다.', token: null });
    }
    res.redirect(`/auth/consent?token=${token}`);
});
app.get('/invite', (req, res) => {
    const clientId = process.env.DISCORD_CLIENT_ID;
    if (!clientId) {
        return res.render('auth.ejs', { stage: 'error', error: '서버 설정 오류: Discord Client ID가 환경 변수에 설정되지 않았습니다.', token: null });
    }
    const INVITE_PERMISSIONS = '397552995334';
    const INVITE_CALLBACK_URI = `${process.env.BASE_URL}/invite/callback`;
    const inviteUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&permissions=${INVITE_PERMISSIONS}&scope=bot&redirect_uri=${encodeURIComponent(INVITE_CALLBACK_URI)}&response_type=code`;
    res.render('invite.ejs', {
        title: '봇 초대하기',
        inviteUrl: inviteUrl
    });
});
app.get('/invite/callback', (req, res) => {
    const { code, guild_id } = req.query;
    if (code && guild_id) {
        res.render('auth.ejs', {
            stage: 'success',
            message: `봇이 서버에 성공적으로 추가되었습니다!\n\n서버 관리 페이지로 돌아가서 /설정 명령어를 사용하세요.`,
            token: null,
            error: null
        });
    } else {
        res.render('auth.ejs', {
            stage: 'error',
            error: '봇 초대가 취소되거나 실패했습니다. 다시 시도해 주십시오.',
            token: null
        });
    }
});
app.get('/auth/consent', async (req, res) => {
    const { token } = req.query;
    const session = await db.get(`session_auth_${token}`);
    if (!session || session.expires < Date.now()) {
        return res.render('auth.ejs', { stage: 'error', error: '세션이 만료되었거나 유효하지 않습니다.', token: null });
    }
    if (session.step === 'consent_agreed') {
        const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(AUTH_CALLBACK_URI)}&scope=identify&state=${token}`;
        return res.redirect(discordAuthUrl);
    }
    res.render('auth_consent.ejs', { stage: 'consent', token: token, error: null });
});
app.post('/auth/consent', async (req, res) => {
    const { token, agree } = req.body;
    const session = await db.get(`session_auth_${token}`);
    if (!session || session.expires < Date.now()) {
        return res.render('auth.ejs', { stage: 'error', error: '세션이 만료되었거나 유효하지 않습니다.', token: null });
    }
    if (agree !== 'on') {
        return res.render('auth.ejs', { stage: 'error', error: '인증을 계속하려면 개인정보 수집 및 이용에 동의해야 합니다.', token: null });
    }
    session.step = 'consent_agreed';
    await db.set(`session_auth_${token}`, session);
    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(AUTH_CALLBACK_URI)}&scope=identify&state=${token}`;
    res.redirect(discordAuthUrl);
});
app.get('/auth/callback', async (req, res) => {
    const { code, state } = req.query;
    const session = await db.get(`session_auth_${state}`);
    if (!session) {
        return res.render('auth.ejs', { stage: 'error', error: '세션이 만료되었거나 유효하지 않습니다.', token: null });
    }
    try {
        const accessToken = await exchangeCodeForToken(code, AUTH_CALLBACK_URI);
        if (!accessToken) {
            throw new Error("Discord 토큰 교환에 실패했습니다.");
        }
        const userResponse = await axios.get('https://discord.com/api/users/@me', { headers: { 'Authorization': `Bearer ${accessToken}` } });
        if (userResponse.data.id !== session.userId) {
            return res.render('auth.ejs', { stage: 'error', error: '인증 요청자와 로그인한 디스코드 계정이 다릅니다.', token: null });
        }
        session.step = 'email_fingerprint';
        session.discordInfo = userResponse.data;
        await db.set(`session_auth_${state}`, session);
        res.render('auth.ejs', { stage: 'email_fingerprint', error: null, token: state });
    } catch (error) {
        console.error("Callback 처리 중 오류 상세:", error.message);
        res.render('auth.ejs', { stage: 'error', error: 'Discord 인증 중 오류가 발생했습니다. (환경 변수, Redirect URI 확인)', token: null });
    }
});
app.post('/request-code', async (req, res) => {
    const { token, fingerprintId, email } = req.body;
    const session = await db.get(`session_auth_${token}`);
    if (!session || session.step !== 'email_fingerprint') {
        return res.render('auth.ejs', { stage: 'error', error: '잘못된 접근입니다.', token: null });
    }
    if (!email.endsWith('@naver.com')) {
        return res.render('auth.ejs', { stage: 'email_fingerprint', error: '네이버 이메일(@naver.com)만 사용할 수 있습니다.', token });
    }
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    session.step = 'code_submit';
    session.fingerprintId = fingerprintId;
    session.email = email;
    session.verificationCode = verificationCode;
    await db.set(`session_auth_${token}`, session);
    try {
        await transporter.sendMail({
            from: `"인증봇" <${process.env.NAVER_EMAIL_USER}@naver.com>`,
            to: email,
            subject: '🔒 디스코드 서버 인증 코드를 입력해주세요.',
            html: `<div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;"><h2 style="color: #5865F2; text-align: center; margin-bottom: 20px;">디스코드 서버 인증 코드</h2><p style="font-size: 16px; color: #333; margin-bottom: 20px;">인증을 계속 진행하려면, 아래 6자리 코드를 인증 페이지에 입력해주세요. 이 코드는 <b>5분 동안만 유효</b>합니다.</p><div style="text-align: center; margin: 30px 0; padding: 15px; background-color: #f0f0f0; border-radius: 8px; border: 2px dashed #5865F2;"><p style="font-size: 32px; font-weight: bold; color: #5865F2; letter-spacing: 5px; margin: 0;">${verificationCode}</p></div><p style="font-size: 14px; color: #777; text-align: center;">만약 본인이 요청한 것이 아니라면, 이 메일을 무시해 주십시오.</p></div>`
        });
        res.render('auth.ejs', { stage: 'code_submit', error: null, token, email });
    } catch (error) {
        console.error('이메일 전송 실패:', error);
        res.render('auth.ejs', { stage: 'email_fingerprint', error: '인증 코드 발송에 실패했습니다. (네이버 SMTP 설정 확인)', token });
    }
});
app.post('/verify', async (req, res) => {
    const { token, code } = req.body;
    const session = await db.get(`session_auth_${token}`);
    if (!session || session.step !== 'code_submit' || session.verificationCode !== code) {
        const errorMsg = (!session || session.step !== 'code_submit') ? '세션이 만료되었거나 잘못된 접근입니다.' : '인증 코드가 올바르지 않습니다.';
        return res.render('auth.ejs', { stage: 'code_submit', error: errorMsg, token, email: session?.email });
    }
    try {
        const guild = await client.guilds.fetch(session.guildId);
        const member = await guild.members.fetch(session.userId);
        const encryptedEmail = encrypt(session.email);
        const isFingerprintDuplicate = await db.has(`fingerprint_${guild.id}_${session.fingerprintId}`);
        const isEmailDuplicate = await db.has(`email_${guild.id}_${encryptedEmail}`);
        let emailSimilarityInfo = { isSimilar: false, matchedEmail: null, matchedUserId: null };
        if (!isEmailDuplicate) {
            const allData = await db.all();
            const guildEmailsData = allData.filter(e => e.id.startsWith(`email_${guild.id}_`));
            const newEmailUser = session.email.split('@')[0];
            for (const entry of guildEmailsData) {
                const storedEmail = decrypt(entry.id.substring(`email_${guild.id}_`.length));
                if (storedEmail.startsWith('DECRYPTION_ERROR')) continue;
                const storedEmailUser = storedEmail.split('@')[0];
                if (levenshtein(newEmailUser, storedEmailUser) <= 2) {
                    emailSimilarityInfo = {
                        isSimilar: true,
                        matchedEmail: storedEmail,
                        matchedUserId: entry.value
                    };
                    break;
                }
            }
        }
        const accountAgeInDays = Math.floor((Date.now() - member.user.createdAt) / 86400000);
        const isBlocked = isFingerprintDuplicate || isEmailDuplicate;
        const userData = {
            discordUser: { id: member.user.id, username: member.user.username, accountAgeInDays, publicFlags: member.user.flags.toArray(), hasAvatar: member.user.avatar !== null, hasBanner: member.user.banner !== null },
            discordMember: { guildId: guild.id },
            systemFootprint: { isFingerprintDuplicate, isEmailDuplicate, isEmailSimilar: emailSimilarityInfo.isSimilar, email: session.email }
        };
        if (isBlocked) {
            const reason = isEmailDuplicate ? 'email_duplicate' : 'fingerprint_duplicate';
            await logAuthAttempt(guild.id, member.id, 'denied', reason, { email: session.email, fingerprintId: session.fingerprintId });
            try { await member.send('디스코드 서버 인증에 실패했습니다. 이미 사용된 이메일 또는 기기 정보로 확인되었습니다. 본계정으로 다시 시도해주세요.'); } catch (dmError) { console.error(`${member.user.tag}님에게 DM 전송 실패:`, dmError); }
            await member.kick('인증 실패: 중복된 이메일 또는 기기 정보 감지').catch(kickError => console.error(`${member.user.tag}님을 추방하는데 실패했습니다:`, kickError));
            res.render('auth.ejs', { stage: 'error', error: '이미 인증에 사용된 이메일 또는 기기 정보입니다.', token: null });
            (async () => {
                userData.systemFootprint.systemVerdict = 'DENIED';
                const analysis = await getGeminiAnalysis(userData);
                await sendLogMessage(guild, 'failure', member, analysis, session, encryptedEmail);
            })();
        } else {
            const verifiedRoleId = await db.get(`config_verified_role_${guild.id}`);
            let roleAssigned = false;
            if (verifiedRoleId) {
                const verifiedRole = guild.roles.cache.get(verifiedRoleId);
                if (verifiedRole) {
                    await member.roles.add(verifiedRole);
                    roleAssigned = true;
                }
            }
            if (!roleAssigned) {
                let fallbackRole = guild.roles.cache.find(r => r.name === '인증');
                if (!fallbackRole) { fallbackRole = await guild.roles.create({ name: '인증', color: 'Green', reason: '인증 시스템 기본 역할' }); }
                await member.roles.add(fallbackRole);
            }
            await db.set(`fingerprint_${guild.id}_${session.fingerprintId}`, member.id);
            await db.set(`email_${guild.id}_${encryptedEmail}`, member.id);
            res.render('auth.ejs', { stage: 'success', message: '성공적으로 인증되어 역할이 부여되었습니다!', token: null, error: null });
            (async () => {
                userData.systemFootprint.systemVerdict = 'ALLOWED';
                const analysis = await getGeminiAnalysis(userData);
                const suspiciousLevels = ['의심', '높음', '매우 높음']
                const logDetails = {
                    email: session.email,
                    fingerprintId: session.fingerprintId,
                    riskLevel: analysis.riskLevel,
                    reasoning: analysis.reasoning
                };
                
                if (emailSimilarityInfo.isSimilar) {
                    logDetails.isEmailSimilar = true;
                    logDetails.matchedEmail = emailSimilarityInfo.matchedEmail;
                    logDetails.matchedUserId = emailSimilarityInfo.matchedUserId;
                }
                
                if (suspiciousLevels.includes(analysis.riskLevel) || emailSimilarityInfo.isSimilar) {
                    await logAuthAttempt(guild.id, member.id, 'warning', `ai_risk:${analysis.riskLevel}`, logDetails);
                    await sendLogMessage(guild, 'warning', member, analysis, session, encryptedEmail);
                } else {
                    await logAuthAttempt(guild.id, member.id, 'allowed', 'success', logDetails);
                    await sendLogMessage(guild, 'success', member, analysis, session, encryptedEmail);
                }
            })();
        }
        await db.delete(`session_auth_${token}`);
    } catch (error) {
        console.error("최종 인증 처리 중 오류:", error);
        res.render('auth.ejs', { stage: 'error', error: '인증 처리 중 서버 오류가 발생했습니다.', token: null });
    }
});
app.get('/dashboard/login', (req, res) => {
    const redirectUri = encodeURIComponent(DASHBOARD_CALLBACK_URI);
    const clientId = process.env.DISCORD_CLIENT_ID;
    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&response_type=code&redirect_uri=${redirectUri}&scope=identify%20guilds`;
    res.redirect(discordAuthUrl);
});
app.get('/dashboard/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.redirect('/dashboard/login');
    try {
        const accessToken = await exchangeCodeForToken(code, DASHBOARD_CALLBACK_URI);
        if (!accessToken) throw new Error("대시보드 로그인 토큰 교환 실패");
        const userResponse = await axios.get('https://discord.com/api/users/@me', { headers: { 'Authorization': `Bearer ${accessToken}` } });
        const guildsResponse = await axios.get('https://discord.com/api/users/@me/guilds', { headers: { 'Authorization': `Bearer ${accessToken}` } });
        const availableGuilds = guildsResponse.data.filter(g => (new PermissionsBitField(BigInt(g.permissions)).has('Administrator') || g.owner) && client.guilds.cache.has(g.id));
        if (availableGuilds.length === 0) {
            return res.render('auth.ejs', { stage: 'error', error: '봇이 참여 중이며 당신이 관리하는 서버를 찾을 수 없습니다.', token: null });
        }
        const sessionToken = uuidv4();
        await db.set(`session_dash_${sessionToken}`, {
            userId: userResponse.data.id,
            availableGuilds,
            expires: Date.now() + 3600000
        });
        res.cookie('dash_session', sessionToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 3600000, sameSite: 'Lax' });
        res.redirect('/dashboard/select');
    } catch (error) {
        console.error("대시보드 OAuth2 오류:", error.message);
        return res.redirect('/dashboard/login');
    }
});
app.get('/dashboard/select', async (req, res) => {
    const sessionToken = req.cookies.dash_session;
    const session = await db.get(`session_dash_${sessionToken}`);
    if (!session || session.expires < Date.now()) {
        await db.delete(`session_dash_${sessionToken}`);
        res.clearCookie('dash_session');
        return res.redirect('/dashboard/login');
    }
    res.render('dashboard_select.ejs', { title: '서버 선택', availableGuilds: session.availableGuilds });
});
app.get('/dashboard', async (req, res) => {
    const sessionToken = req.cookies.dash_session;
    const guildId = req.query.guildId;
    const session = await db.get(`session_dash_${sessionToken}`);
    if (!session || session.expires < Date.now()) { await db.delete(`session_dash_${sessionToken}`); res.clearCookie('dash_session'); return res.redirect('/dashboard/login'); }
    if (!session.availableGuilds.some(g => g.id === guildId)) { return res.render('auth.ejs', { stage: 'error', error: '접근 권한이 없는 서버입니다.', token: null }); }
    try {
        const allData = await db.all();
        const verifiedUsers = allData.filter(e => e.id.startsWith(`email_${guildId}_`)).map(e => ({ decryptedEmail: decrypt(e.id.substring(`email_${guildId}_`.length)), discordId: e.value }));
        const fingerprints = allData.filter(e => e.id.startsWith(`fingerprint_${guildId}_`)).map(e => ({ fingerprintId: e.id.substring(`fingerprint_${guildId}_`.length), discordId: e.value }));
        const currentGuild = client.guilds.cache.get(guildId) || { name: '알 수 없는 서버' };
        const authLogs = await db.get(`auth_logs_${guildId}`) || [];
        const now = Date.now();
        const oneDay = 86400000;
        const allowedCount = authLogs.filter(log => log.result === 'allowed').length;
        const deniedCount = authLogs.filter(log => log.result === 'denied').length;
        const warningCount = authLogs.filter(log => log.result === 'warning').length;
        const todayVerifiedCount = authLogs.filter(log => log.result === 'allowed' && (now - log.timestamp < oneDay)).length;
        const ageBins = { '7일 미만': 0, '30일 미만': 0, '90일 미만': 0, '90일 이상': 0 };
        const members = await currentGuild.members.fetch({ user: verifiedUsers.map(u => u.discordId) }).catch(() => new Map());
        members.forEach(member => {
            const ageDays = (now - member.user.createdAt.getTime()) / oneDay;
            if (ageDays < 7) ageBins['7일 미만']++; else if (ageDays < 30) ageBins['30일 미만']++; else if (ageDays < 90) ageBins['90일 미만']++; else ageBins['90일 이상']++;
        });
        const timeSeriesData = { labels: [], allowed: [], denied: [], warning: [] };
        const dailyData = {};
        const thirtyDaysAgo = now - 30 * oneDay;
        for (const log of authLogs) {
            if (log.timestamp > thirtyDaysAgo) {
                const date = new Date(log.timestamp).toISOString().split('T')[0];
                if (!dailyData[date]) { dailyData[date] = { allowed: 0, denied: 0, warning: 0 }; }
                if (dailyData[date][log.result] !== undefined) dailyData[date][log.result]++;
            }
        }
        for (let i = 29; i >= 0; i--) {
            const date = new Date(now - i * oneDay).toISOString().split('T')[0];
            timeSeriesData.labels.push(date.substring(5));
            timeSeriesData.allowed.push(dailyData[date]?.allowed || 0);
            timeSeriesData.denied.push(dailyData[date]?.denied || 0);
            timeSeriesData.warning.push(dailyData[date]?.warning || 0);
        }
        const stats = { totalEmails: verifiedUsers.length, totalFingerprints: fingerprints.length, todayVerifiedCount, chartData: { allowed: allowedCount, denied: deniedCount, warning: warningCount }, ageDistributionChart: { labels: Object.keys(ageBins), data: Object.values(ageBins), riskCount: warningCount }, timeSeriesData };
        res.render('dashboard.ejs', { title: '관리자 대시보드', verifiedUsers, fingerprints, guildName: currentGuild.name, guildId, error: ENCRYPTION_KEY ? null : '이메일 암호화 키가 설정되지 않았습니다.', stats });
    } catch (error) {
        console.error("대시보드 데이터 로드 오류:", error);
        res.render('auth.ejs', { stage: 'error', error: '데이터 로드 중 오류가 발생했습니다.', token: null });
    }
});
app.get('/dashboard/api/user/:userId', async (req, res) => {
    const sessionToken = req.cookies.dash_session;
    const session = await db.get(`session_dash_${sessionToken}`);
    const { guildId } = req.query;
    const { userId } = req.params;
    if (!session || session.expires < Date.now() || !guildId) {
        return res.status(401).json({ error: '인증되지 않았거나 잘못된 요청입니다.' });
    }
    if (!session.availableGuilds.some(g => g.id === guildId)) {
        return res.status(403).json({ error: '해당 서버에 대한 접근 권한이 없습니다.' });
    }
    try {
        const allData = await db.all();
        const allGuildLogs = await db.get(`auth_logs_${guildId}`) || [];
        const userAuthLogs = allGuildLogs.filter(log => log.userId === userId);
        const userDiscordInfo = await client.users.fetch(userId).catch(() => null);
        let userVerificationData = {
            email: null,
            fingerprint: null,
            similarEmailInfo: null
        };
        const emailEntry = allData.find(e => e.id.startsWith(`email_${guildId}_`) && e.value === userId);
        if (emailEntry) {
            userVerificationData.email = decrypt(emailEntry.id.substring(`email_${guildId}_`.length));
        }
        const fingerprintEntry = allData.find(e => e.id.startsWith(`fingerprint_${guildId}_`) && e.value === userId);
        if (fingerprintEntry) {
            userVerificationData.fingerprint = fingerprintEntry.id.substring(`fingerprint_${guildId}_`.length);
        }
        const latestLog = userAuthLogs.slice().reverse().find(log => log.result === 'allowed' || log.result === 'warning');
        if (latestLog && latestLog.isEmailSimilar) {
            userVerificationData.similarEmailInfo = {
                isSimilar: true,
                matchedEmail: latestLog.matchedEmail,
                matchedUserId: latestLog.matchedUserId
            };
        }
        let relatedAccounts = { byFingerprint: [], bySimilarEmail: [] };
        if (fingerprintEntry) {
            relatedAccounts.byFingerprint = allData
                .filter(e => e.id === fingerprintEntry.id && e.value !== userId)
                .map(e => e.value);
        }
        relatedAccounts.bySimilarEmail = allGuildLogs
            .filter(log => log.matchedUserId === userId)
            .map(log => ({
                userId: log.userId,
                email: log.email,
                matchedEmail: log.matchedEmail
            }));
        res.json({
            discordInfo: userDiscordInfo ? {
                username: userDiscordInfo.username,
                id: userDiscordInfo.id,
                avatarURL: userDiscordInfo.displayAvatarURL(),
                createdAt: userDiscordInfo.createdAt.toISOString()
            } : { username: '알 수 없음', id: userId },
            verificationData: userVerificationData,
            relatedAccounts,
            authLogs: userAuthLogs
        });
    } catch (error) {
        console.error(`[API User Details] 오류:`, error);
        res.status(500).json({ error: '사용자 정보를 가져오는 중 서버 오류가 발생했습니다.' });
    }
});
app.get('/dashboard/settings', async (req, res) => {
    const sessionToken = req.cookies.dash_session;
    const guildId = req.query.guildId;
    const session = await db.get(`session_dash_${sessionToken}`);
    if (!session || session.expires < Date.now() || !guildId) return res.redirect('/dashboard/login');
    if (!session.availableGuilds.some(g => g.id === guildId)) return res.render('auth.ejs', { stage: 'error', error: '접근 권한이 없는 서버입니다.', token: null });
    try {
        const guild = await client.guilds.fetch(guildId);
        if (!guild) throw new Error('서버를 찾을 수 없습니다.');
        const roles = guild.roles.cache
            .filter(role => !role.managed && role.name !== '@everyone')
            .map(role => ({ id: role.id, name: role.name, color: role.hexColor }))
            .sort((a, b) => a.name.localeCompare(b.name));
        const currentSettings = {
            verifiedRoleId: await db.get(`config_verified_role_${guildId}`) || null,
            logRoleId: await db.get(`config_log_role_${guildId}`) || null
        };
        res.render('dashboard_settings.ejs', {
            title: `${guild.name} - 설정`,
            guild,
            roles,
            settings: currentSettings,
            success: req.query.success || null
        });
    } catch (error) {
        console.error('[Settings Page] 오류:', error);
        res.render('auth.ejs', { stage: 'error', error: '설정 페이지를 로드하는 중 오류가 발생했습니다.', token: null });
    }
});
app.post('/dashboard/settings', async (req, res) => {
    const sessionToken = req.cookies.dash_session;
    const { guildId, verifiedRoleId, logRoleId } = req.body;
    const session = await db.get(`session_dash_${sessionToken}`);
    if (!session || session.expires < Date.now() || !guildId) return res.status(401).send('Unauthorized');
    if (!session.availableGuilds.some(g => g.id === guildId)) return res.status(403).send('Forbidden');

    try {
        if (verifiedRoleId === 'none') {
            await db.delete(`config_verified_role_${guildId}`);
        } else {
            await db.set(`config_verified_role_${guildId}`, verifiedRoleId);
        }
        if (logRoleId === 'none') {
            await db.delete(`config_log_role_${guildId}`);
        } else {
            await db.set(`config_log_role_${guildId}`, logRoleId);
        }
        res.redirect(`/dashboard/settings?guildId=${guildId}&success=true`);
    } catch (error) {
        console.error('[Save Settings] 오류:', error);
        res.status(500).send('설정 저장 중 오류가 발생했습니다.');
    }
});
async function sendLogMessage(guild, resultType, member, analysis, session, encryptedEmail) {
    try {
        const logThreads = await db.get(`log_threads_${guild.id}`);
        if (!logThreads) return;
        const threadId = logThreads[resultType];
        if (!threadId) return;

        const thread = await client.channels.fetch(threadId);
        if (!thread) return;
        if (thread.archived) {
            await thread.setArchived(false);
        }
        const logRoleId = await db.get(`config_log_role_${guild.id}`);
        let mentionContent = '';

        if (logRoleId && (resultType === 'warning' || resultType === 'failure')) {
            mentionContent = `<@&${logRoleId}>`;
        }
        const decryptedEmail = decrypt(encryptedEmail);
        const embed = new EmbedBuilder()
            .setAuthor({ name: member.user.tag, iconURL: member.user.displayAvatarURL() })
            .setTimestamp()
            .setFooter({ text: `User ID: ${member.id}` });
        const components = [];
        if (resultType === 'success') {
            embed.setColor('Green').setTitle('✅ 인증 성공').addFields(
                { name: 'AI 위험도', value: `${analysis.riskLevel}`, inline: true },
                { name: 'AI 분석 요약', value: analysis.reasoning, inline: false },
                { name: '인증된 이메일', value: `\`${decryptedEmail}\``, inline: false },
                { name: '기기 식별자 (Fingerprint)', value: `\`${session.fingerprintId}\``, inline: false }
            );
        } else if (resultType === 'failure') {
            embed.setColor('Red').setTitle('🚨 인증 실패 (규칙 위반)').addFields(
                { name: 'AI 위험도', value: `${analysis.riskLevel}`, inline: true },
                { name: 'AI 분석 요약', value: analysis.reasoning, inline: false },
                { name: '시도한 이메일', value: `\`${session.email}\``, inline: false },
                { name: '기기 식별자 (Fingerprint)', value: `\`${session.fingerprintId}\``, inline: false }
            );
        } else if (resultType === 'warning') {
            embed.setColor('Orange').setTitle('⚠️ 인증 경고 (수동 확인 필요)').addFields(
                { name: 'AI 위험도', value: `**${analysis.riskLevel}**`, inline: true },
                { name: 'AI 분석 요약', value: analysis.reasoning, inline: false },
                { name: '인증된 이메일', value: `\`${decryptedEmail}\``, inline: false },
                { name: '기기 식별자 (Fingerprint)', value: `\`${session.fingerprintId}\``, inline: false }
            );
            const row = new ActionRowBuilder().addComponents(
                new ButtonBuilder().setCustomId(`approve-user_${member.id}`).setLabel('승인').setStyle(ButtonStyle.Success),
                new ButtonBuilder().setCustomId(`kick-user_${member.id}`).setLabel('추방 (Kick)').setStyle(ButtonStyle.Danger),
                new ButtonBuilder().setCustomId(`investigate-user_${member.id}`).setLabel('개별 조사').setStyle(ButtonStyle.Secondary)
            );
            components.push(row);
        }
        await thread.send({ embeds: [embed], components: components });
    } catch (error) {
        console.error('[LOG] 로그 메시지 전송 중 오류 발생:', error);
    }
}
async function postOrUpdateVerificationMessage(channel) {
    const embed = new EmbedBuilder()
        .setColor('#5865F2').setTitle('🔒 서버 인증 안내')
        .setDescription('서버 활동을 위해서는 본인 확인 인증이 필요합니다.\n\n아래 **[인증 시작하기]** 버튼을 눌러주세요.')
        .setFooter({ text: '다중 계정 및 악성 유저 방지를 위한 절차입니다.' });
    const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('start_verification').setLabel('인증 시작하기').setStyle(ButtonStyle.Success).setEmoji('✅')
    );
    try {
        const messages = await channel.messages.fetch({ limit: 1 });
        const lastMessage = messages.first();
        if (lastMessage && lastMessage.author.id === client.user.id) {
            await lastMessage.edit({ embeds: [embed], components: [row] });
        } else {
            await channel.send({ embeds: [embed], components: [row] });
        }
    } catch (error) { console.error("인증 메시지 전송/수정 실패:", error); }
}
async function createLogThreads(channel, adminUser, ownerId) {
    const threadDefinitions = {
        failure: '차단',
        warning: '경고',
        success: '성공'
    };
    const logThreadIds = {};
    const logRoleId = await db.get(`config_log_role_${channel.guildId}`);
    const mentionString = logRoleId ? `<@&${logRoleId}>` : '관리자';
    for (const [type, name] of Object.entries(threadDefinitions)) {
        try {
            let thread = channel.threads.cache.find(t => t.name === name && t.ownerId === client.user.id);
            if (!thread) {
                thread = await channel.threads.create({
                    name: name,
                    autoArchiveDuration: 10080,
                    type: ChannelType.PrivateThread,
                    reason: '인증 시스템 로그 채널'
                });
                let welcomeMessage = '';
                switch (type) {
                    case 'failure':
                        welcomeMessage = `${mentionString}, 이 스레드는 **인증 실패** 로그 채널입니다. 규칙 위반으로 차단된 사용자의 기록이 전송됩니다.`;
                        break;
                    case 'warning':
                        welcomeMessage = `${mentionString}, 이 스레드는 **인증 경고** 로그 채널입니다. AI가 잠재적 위험을 감지하여 관리자의 확인이 필요한 기록이 전송됩니다.`;
                        break;
                    case 'success':
                        welcomeMessage = `${mentionString}, 이 스레드는 **인증 성공** 로그 채널입니다. 모든 성공 기록이 여기에 보관됩니다.`;
                        break;
                }
                if (welcomeMessage) {
                    await thread.send(welcomeMessage);
                }
            }
            logThreadIds[type] = thread.id;
        } catch (error) {
            console.error(`${name} 비공개 스레드 생성 실패:`, error);
        }
    }
    await db.set(`log_threads_${channel.guildId}`, logThreadIds);
}
async function saveConfigBackup(guildId) {
    try {
        let backupData = {};
        try {
            const fileData = await fs.readFile(BACKUP_FILE_PATH, 'utf8');
            backupData = JSON.parse(fileData);
        } catch (error) {
            if (error.code !== 'ENOENT') throw error;
        }
        const verificationChannelId = await db.get(`verification_channel_${guildId}`);
        const logThreadIds = await db.get(`log_threads_${guildId}`);
        if (verificationChannelId && logThreadIds) {
            backupData[guildId] = { verificationChannelId, logThreadIds };
            await fs.writeFile(BACKUP_FILE_PATH, JSON.stringify(backupData, null, 2));
            console.log(`[BACKUP] 서버 ${guildId}의 설정을 config_backup.json에 저장했습니다.`);
        }
    } catch (error) {
        console.error('[BACKUP] 설정 백업 중 오류 발생:', error);
    }
}
async function restoreConfigFromBackup() {
    console.log('[RESTORE] 백업 파일에서 설정 복원을 시도합니다...');
    try {
        const fileData = await fs.readFile(BACKUP_FILE_PATH, 'utf8');
        const backupData = JSON.parse(fileData);
        for (const guildId in backupData) {
            const hasChannel = await db.has(`verification_channel_${guildId}`);
            const hasThreads = await db.has(`log_threads_${guildId}`);
            if (!hasChannel || !hasThreads) {
                const { verificationChannelId, logThreadIds } = backupData[guildId];
                await db.set(`verification_channel_${guildId}`, verificationChannelId);
                await db.set(`log_threads_${guildId}`, logThreadIds);
                console.log(`[RESTORE] 서버 ${guildId}의 설정을 백업에서 DB로 복원했습니다.`);
            }
        }
    } catch (error) {
        if (error.code === 'ENOENT') {
            console.log('[RESTORE] config_backup.json 파일이 없어 복원을 건너뜁니다.');
        } else {
            console.error('[RESTORE] 백업 파일에서 설정 복원 중 오류 발생:', error);
        }
    }
}
async function startSessionCleaner() {
    const INTERVAL = 60 * 60 * 1000;
    const cleanExpiredSessions = async () => {
        try {
            const allData = await db.all();
            const now = Date.now();
            let cleanedCount = 0;
            for (const entry of allData) {
                if (entry.id.startsWith('session_auth_') || entry.id.startsWith('session_dash_')) {
                    if (entry.value.expires < now) {
                        await db.delete(entry.id);
                        cleanedCount++;
                    }
                }
            }
            if (cleanedCount > 0) {
                console.log(`[SESSION CLEANER] 만료된 세션 ${cleanedCount}개를 정리했습니다.`);
            }
        } catch (error) {
            console.error('[SESSION CLEANER] 세션 정리 중 오류 발생:', error);
        }
    };
    await cleanExpiredSessions();
    setInterval(cleanExpiredSessions, INTERVAL);
    console.log("[SCHEDULER] 세션 자동 정리 스케줄러가 시작되었습니다 (1시간 간격).");
}

client.on(Events.GuildMemberRemove, async member => {
    const guildId = member.guild.id;
    const userId = member.user.id;
    const deletionTime = Date.now() + (7 * 24 * 60 * 60 * 1000);
    await db.set(`deletion_schedule_${guildId}_${userId}`, {
        userId: userId,
        guildId: guildId,
        scheduledFor: deletionTime
    });
    console.log(`[SCHEDULED] 서버 ${guildId}에서 사용자 ${member.user.tag}의 데이터 파기를 7일 후 (${new Date(deletionTime).toISOString()})로 예약했습니다.`);
});
async function startDeletionScheduler() {
    const INTERVAL = 6 * 60 * 60 * 1000;
    async function executeExpiredDestruction() {
        const now = Date.now();
        const allSchedules = await db.all();
        const expiredSchedules = allSchedules.filter(entry => entry.id.startsWith('deletion_schedule_') && entry.value.scheduledFor < now);
        if (expiredSchedules.length > 0) {
            console.warn(`[AUTO-RECOVERY] 재부팅으로 인해 누락된 만료 예약 ${expiredSchedules.length}건을 즉시 처리합니다.`);
        }
        for (const scheduleEntry of expiredSchedules) {
            const { userId, guildId } = scheduleEntry.value;
            const success = await destroyUserData(guildId, userId);
            if (success) {
                await db.delete(scheduleEntry.id);
                console.log(`[AUTO-DESTROY] 복구: 예약된 사용자 ${userId} 데이터가 파기되었습니다.`);
            }
        }
    }
    await executeExpiredDestruction();
    setInterval(async () => {
        await executeExpiredDestruction();
    }, INTERVAL);
    console.log("[SCHEDULER] 자동 데이터 파기 스케줄러가 시작되었습니다 (6시간 간격 및 시작 시 복구).");
}
const token = process.env.DISCORD_BOT_TOKEN ? process.env.DISCORD_BOT_TOKEN.trim() : null;
if (!token) {
    console.error("🚨 DISCORD_BOT_TOKEN 환경 변수가 설정되지 않았습니다.");
    process.exit(1);
}
client.login(token)
    .then(() => {
        const PORT = process.env.PORT || 4000;
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`[WEB] 웹 서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
            console.log(`[WEB] 대시보드 로그인: ${process.env.BASE_URL}/dashboard/login`);
        });
    })
    .catch((error) => {
        console.error("🚨 Discord 로그인 실패: 유효하지 않은 토큰입니다.", error);
        process.exit(1);
    });
