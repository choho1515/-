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

async function exchangeCodeForToken(code, redirectUri, retries = 3) {
    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
    
    for (let i = 0; i < retries; i++) {
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
            const errorData = error.response?.data || { error: 'Unknown Error' };
            const status = error.response?.status;
            
            if (status === 400 && errorData.error === 'invalid_grant') {
                console.error("OAuth2 토큰 교환 최종 실패: 무효한 인증 코드. 재시도하지 않습니다.", errorData);
                return null;
            }

            if (status === 429) {
                const retryAfter = error.response.headers['retry-after'] ? parseInt(error.response.headers['retry-after']) * 1000 : 2000;
                if (i < retries - 1) {
                    console.warn(`[RATE LIMIT] 토큰 교환 실패 (429). ${i + 1}/${retries}회 재시도. ${retryAfter / 1000}초 대기 후 재시도합니다.`);
                    await sleep(retryAfter + (Math.random() * 500));
                    continue;
                }
            }
            
            console.error("OAuth2 토큰 교환 최종 실패:", errorData, `HTTP Status: ${status}`);
            return null;
        }
    }
    return null;
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
당신은 온라인 커뮤니티의 악성 사용자를 식별하는 최고의 사이버 보안 분석가입니다. 당신의 임무는 규칙 기반 시스템의 결과를 넘어서 복합적인 요소를 고려하여 최종 위험도를 '매우 낮음', '낮음', '보통', '의심', '높음', '매우 높음'의 6단계로 분석하는 것입니다.

# 분석 데이터
${JSON.stringify(userData, null, 2)}

# 분석 지침 (복합적 위험도 판단)
1.  시스템 판정 (\`systemFootprint.systemVerdict\`):
    - 값이 'TRUE_DUPLICATE'이면 규칙 기반 차단입니다. 위험도를 '매우 높음'으로 고정하고 분석 요약에 그 사실을 명확히 언급하세요.
    - 값이 'RE_AUTHENTICATION'이면 기존 사용자의 재인증입니다. 아래 2~4단계를 분석하되, 오래된 계정 및 활성 플래그가 발견되면 잠재적 위험(유사 이메일 등)을 강력하게 상쇄하여 최종 위험도를 '낮음' 이하로 낮추세요.

2.  추가 보안 정보 활용 및 가산 요소: \`systemFootprint.clientIp\`와 \`systemFootprint.geoData\`를 확인하여, 인증 시도 IP의 지역(\`geoData.country\`)이 예상 주 사용 지역(예: 한국, 대한민국)과 다르거나, 비정상적인 해외/고위험 지역(예: 알려진 VPN 서버 위치)으로 판단되면 지역적 이상 징후로 분석에 반영하세요. 이러한 이상 징후는 위험도를 1단계 높일 수 있습니다.

3.  위험 요소 점수 부여 (systemVerdict가 'NEW_USER'이거나 'RE_AUTHENTICATION'인 경우):
    - 초기 위험도: '매우 낮음'으로 시작합니다.
    - 가산 요소: 다음 요소가 발견될 때마다 위험도를 한 단계씩 높입니다.
        - 유사 이메일 주소 (\`isEmailSimilar\`): \`true\`일 경우: 1단계 상승
        - 신규 계정 (\`accountAgeInDays\` < 7일): 1단계 상승
        - 의미 없는 이름 패턴: 사용자 이름이 'user' + '숫자' 등 의미 없는 조합일 경우: 1단계 상승

4.  감산 요소 (신뢰도 가산):
    - 매우 오래된 계정 (\`accountAgeInDays\` >= 90일): 1단계 하락 (단, 최종 위험도는 '매우 낮음' 미만으로 내려가지 않음)
    - 활성 플래그 보유: \`publicFlags\`에 'HypeSquad', 'Premium Early Supporter', 'Active Developer' 등 활성 플래그가 포함된 경우: 1단계 하락 (단, 최종 위험도는 '매우 낮음' 미만으로 내려가지 않음)

5.  최종 판단 및 분석 요약:
    - 위 규칙들을 종합하여 최종 위험도를 결정하세요. 모든 위험 요소가 상쇄되거나 없다면 '매우 낮음'으로 판단합니다.
    - [필수 조정]: 만약 유사 이메일 (\`isEmailSimilar\`: \`true\`)이 감지되었다면, 모든 상쇄 요인을 고려한 최종 위험도는 **'의심' 미만**으로 내려갈 수 없습니다. (즉, 최소 '의심' 또는 그 이상으로 유지해야 합니다.)
    - 분석 요약에는 최종 위험도와 그 근거(특히 상쇄 요인 및 지역 정보)를 명확히 설명해야 합니다.

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

    const dashboardCommand = new SlashCommandBuilder()
        .setName('대시보드')
        .setDescription('웹 관리자 대시보드 링크를 표시합니다.')
        .setDefaultMemberPermissions(PermissionsBitField.Flags.Administrator);
    await client.application.commands.set([setupCommand, helpCommand, dashboardCommand]);
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
    if (interaction.isCommand() && interaction.commandName === '대시보드') {
        await interaction.deferReply({ ephemeral: true });

        if (!interaction.member.permissions.has(PermissionsBitField.Flags.Administrator)) {
            return interaction.editReply({ content: '🚫 이 명령어를 사용할 권한이 없습니다.', ephemeral: true });
        }

        const dashboardLoginUrl = `${process.env.BASE_URL}/dashboard/login`;
        const dashboardSelectUrl = `${process.env.BASE_URL}/dashboard/select`;
        const dashboardGuildUrl = `${process.env.BASE_URL}/dashboard?guildId=${interaction.guildId}`;

        const embed = new EmbedBuilder()
            .setColor('#5865F2')
            .setTitle(`🌐 ${interaction.guild.name} 서버 대시보드`)
            .setDescription('아래 버튼을 클릭하여 웹 관리자 대시보드에 접속하세요.\n\n대시보드는 **Discord 계정으로 로그인**이 필요하며, 로그인 후 해당 서버를 선택해야 합니다.')
            .addFields(
                { name: '1️⃣ 일반 로그인', value: `먼저 Discord 로그인을 진행하고 서버를 선택하세요.`, inline: false },
                { name: '2️⃣ 직접 접속 (추천)', value: `로그인 후 **바로 이 서버**의 대시보드로 이동합니다.`, inline: false }
            )
            .setFooter({ text: '세션 만료 시 다시 로그인해야 합니다.' })
            .setTimestamp();

        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setLabel('대시보드 로그인')
                .setStyle(ButtonStyle.Link)
                .setURL(dashboardLoginUrl),
            new ButtonBuilder()
                .setLabel('이 서버 대시보드로 바로가기')
                .setStyle(ButtonStyle.Link)
                .setURL(dashboardGuildUrl)
        );

        await interaction.editReply({ embeds: [embed], components: [row], ephemeral: true });
    }
    if (interaction.isCommand() && interaction.commandName === '설정') {
        await interaction.deferReply({ ephemeral: true });
        if (!interaction.member.permissions.has(PermissionsBitField.Flags.Administrator)) {
            return interaction.editReply({ content: '🚫 이 명령어를 사용할 권한이 없습니다.' });
        }
        const channel = interaction.options.getChannel('채널');
        const role = interaction.options.getRole('역할');
        try {
            await db.set(`verification_channel_${interaction.guildId}`, channel.id);
            await db.set(`config_log_role_${interaction.guildId}`, role.id);
            await createLogThreads(channel, interaction.user, interaction.guild.ownerId);
            await postOrUpdateVerificationMessage(channel);
            await saveConfigBackup(interaction.guildId);
            return interaction.editReply({ content: `✅ 이제 ${channel} 채널에서 인증을 시작할 수 있습니다. 설정이 DB와 백업 파일에 모두 저장되었습니다. 알림 역할은 **${role.name}**으로 설정되었습니다.` });
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
        
        const embed = new EmbedBuilder()
            .setColor('#5865F2')
            .setTitle('🔒 인증 시작하기')
            .setDescription('아래 버튼을 클릭하여 인증을 계속 진행해주세요.\n\n이 링크는 **5분**간 유효합니다.')
            .setTimestamp()
            .setFooter({ text: `개인정보 보호를 위해 이 메시지는 ${interaction.user.tag}님에게만 보입니다.` });
            
        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setLabel('인증 페이지로 이동')
                .setStyle(ButtonStyle.Link)
                .setURL(authUrl)
                .setEmoji('✅')
        );

        return interaction.editReply({ 
            embeds: [embed],
            components: [row],
            ephemeral: true,
        });
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
        title: '환영합니다! - 강화된 인증 시스템',
        contentHtml: markedParse(whyNeededMarkdown)
    });
});

app.get('/QnA', async (req, res) => {
    const parser = await loadMarked();
    const qnaMarkdown = `
# 자주 묻는 질문 (Q&A)

## Q: 왜 네이버 이메일만 사용해야 하나요?
> A: 네이버 이메일은 국내에서 가장 널리 사용되면서도, 임시 이메일이나 일회용 이메일 서비스보다 **본인 확인 절차가 엄격**합니다. 악성 사용자들이 쉽게 버릴 수 있는 해외 임시 메일 사용을 막아 **인증의 신뢰도**를 높이고, 다중 계정 시도의 진입 장벽을 높이기 위함입니다.

## Q: '기기 지문(Fingerprint ID)'은 무엇이며, 제 개인정보를 수집하나요?
> A: 기기 지문(Fingerprint ID)은 사용자의 **IP 주소, 브라우저 설정(해상도, 폰트), 운영체제 정보** 등을 조합하여 생성되는 **고유 식별자**입니다.
<div class="fingerprint-danger-box">
    🚨 <b>주의: 이는 여러분의 이름, 전화번호 등 어떠한 신상 정보도 수집하지 않습니다.</b>
    <br>
    수집 목적은 오직 <strong>다중 계정(부계정) 생성을 감지</strong>하기 위함이며, 동일 기기에서 여러 계정으로 인증을 시도하는 것을 막는 것이 핵심 기능입니다. 지문 정보와 인증된 이메일은 암호화되어 저장됩니다.
</div>

## Q: 인증에 실패하고 서버에서 추방당했어요. 왜 그런가요?
> A: 시스템이 **이미 다른 Discord 계정에서 사용 중인 이메일 주소**나 <strong>기기 지문 정보(Fingerprint ID)</strong>를 감지했을 가능성이 높습니다.
> * **핵심 원칙**: 1개의 기기는 1개의 Discord 계정만 인증할 수 있습니다.
> * **대응 방법**: 부계정이 아닌 **본계정으로 인증을 시도**했는지 확인해주세요. 오류라고 판단되면, 관리자에게 문의해주십시오.

## Q: 이전에 인증했던 계정으로 다시 서버에 들어왔는데, 문제가 되나요?
> A: 아닙니다. 시스템은 사용자의 이메일 또는 기기 지문 기록이 현재 Discord ID와 일치하는 것을 확인하면, 이를 <strong>'성공적인 재인증/복귀'</strong>로 간주하고 역할을 즉시 부여합니다. 이 경우 추방당하지 않으며, 재인증 기록이 로그 스레드에 남습니다.

---

# 관리자 관련 질문 (Administrator Q&A)

## Q: AI 분석 로그의 '경고'와 위험도 등급은 무엇을 기준으로 판단되나요?
> A: '경고'는 AI 분석 시스템이 잠재적 위험 요소를 감지하여 **관리자의 수동 검토**가 필요함을 알리는 알림입니다. 주요 판단 기준은 다음과 같습니다.
> * **유사 이메일 주소 감지:** 기존 인증 사용자와 이메일 주소가 유사하여 '의심' 이상의 위험도를 유지합니다.
> * **신규 계정:** Discord 계정 생성일이 7일 미만인 경우.
> 
> AI는 계정 연령 등의 신뢰도 요소를 복합적으로 고려하여 최종 위험도를 결정합니다.

## Q: 대시보드에서 '유사 이메일 감지'와 '동일 기기 사용자'는 무엇을 의미하나요?
> A: 이 항목들은 관리자가 다중 계정 시도를 파악하는 핵심 정보입니다.
> * **유사 이메일 감지:** 이메일 주소의 로컬 파트(아이디)가 기존 인증 사용자와 매우 유사할 때(예: 'user1' vs 'user2') AI가 경고하는 것으로, 수동 부계정 생성 시도를 의미할 수 있습니다.
> * **동일 기기 사용자:** 동일한 기기 지문(Fingerprint ID)으로 인증된 다른 Discord ID 목록입니다. 이는 **규칙 기반 차단 시스템이 걸러내지 못한** 잠재적 부계정의 징후일 수 있습니다.
`;
    res.render('home.ejs', {
        title: '인증 시스템 Q&A',
        contentHtml: parser(qnaMarkdown)
    });
});

app.get('/tos', async (req, res) => {
    const parser = await loadMarked();
    const tosMarkdown = `
# 이용 약관 (Terms of Service)

## 1. 약관의 효력 및 변경
본 약관은 Verita 봇 서비스를 이용하는 모든 사용자에게 적용되며, 서비스를 이용함으로써 본 약관에 동의하는 것으로 간주합니다.
* **약관 변경:** 본 약관은 서비스의 효율적인 운영을 위해 사전 통보 없이 변경될 수 있으며, 변경된 약관은 웹페이지에 게시되는 즉시 효력이 발생합니다.

## 2. 서비스의 목적 및 이용 제한
본 시스템은 Discord 서버의 보안 강화를 목적으로 하며, 다중 계정 및 악성 사용자 활동 방지를 주된 목적으로 합니다.
* **사용자 책임:** 사용자는 Discord 커뮤니티 가이드라인 및 대한민국 관련 법령을 준수해야 합니다.
* **이용 제한 사유:** 시스템 악용, 무단 접근 시도, 서비스의 정상적인 운영을 방해하는 행위, 불법적인 목적으로의 서비스 이용 시 <strong>영구적인 서비스 이용 제한(차단/추방)</strong>이 적용될 수 있습니다.

## 3. 데이터 수집 및 이용
본 서비스는 안정적인 보안 시스템 유지를 위해 다음 정보를 수집 및 이용합니다.
* **수집 정보:** Discord 사용자 ID, 네이버 이메일 주소 (암호화), 기기 고유 식별자 (Fingerprint ID), 인증 로그.
* **이용 목적:** 다중 계정 감지, 부정 인증 방지, AI 기반 위험 분석 및 관리자용 대시보드 제공.
* **데이터 관리:** 수집된 모든 정보는 암호화되어 안전하게 보관되며, 개인정보 처리방침에 명시된 기간 동안만 보유됩니다.

## 4. 서비스의 중단 및 면책 조항
* **서비스 중단:** 시스템 유지보수, 서버 오류, 불가항력적인 상황(천재지변, 정부 명령 등)으로 인해 서비스가 일시적 또는 영구적으로 중단될 수 있으며, 이로 인한 사용자 피해에 대해 시스템 개발자는 책임지지 않습니다.
* **면책 조항:** 본 시스템은 서버 보안 강화를 위한 보조 도구이며, 모든 유형의 악성 행위를 100% 방지함을 보장하지 않습니다. 시스템의 오류나 오작동으로 인해 발생하는 사용자의 손해에 대해 시스템 개발자는 법적 책임을 지지 않습니다.

## 5. 문의 및 분쟁 해결
본 약관에 관한 문의사항이나 시스템 관련 분쟁 발생 시, 먼저 Discord 서버 관리자를 통해 해결을 시도해야 합니다.
`;
    res.render('home.ejs', {
        title: '서비스 이용 약관',
        contentHtml: parser(tosMarkdown)
    });
});

app.get('/privacy', async (req, res) => {
    const parser = await loadMarked();
    const privacyMarkdown = `
<aside style="background-color: #fff3cd; border-left: 5px solid #ffc107; padding: 15px; margin-bottom: 20px; border-radius: 5px; color: #1f2937;">
📌 <b>Notice</b><br>2025년 09월 30일 부터 개정된 개인정보 처리방침이 시행됩니다.
</aside>

# 개인정보 처리방침 (Verita 봇)

## 1. 개인정보 처리 목적
본 시스템 (Verita 봇)은 다음의 목적을 위하여 개인정보를 처리하고 있으며, 처리하고 있는 개인정보는 목적 이외의 용도로는 이용되지 않습니다.

* 이용자 및 서버에 대한 서비스 제공 (다중 계정 및 악성 사용자 방지)
* Discord 커뮤니티 가이드라인 준수 지원 및 보안 유지

## 2. 개인정보의 처리 및 보유 기간
본 시스템은 정보주체로부터 개인정보 수집 시에 동의 받은 기간 내에서 개인정보를 처리·보유합니다.

| 수집 항목 | 보유 기간 | 비고 |
| :--- | :--- | :--- |
| 디스코드 사용자 ID | 서비스 이용 기간 (서버 탈퇴 시 7일 후 파기 예약) | 계정 식별 및 역할 부여 목적 |
| 네이버 이메일 주소 (암호화) | 서비스 이용 기간 (서버 탈퇴 시 7일 후 파기 예약) | 다중 계정 및 이메일 중복 확인 목적 |
| 기기 고유 식별자 (Fingerprint ID) | 서비스 이용 기간 (서버 탈퇴 시 7일 후 파기 예약) | 기기 중복 확인 및 부정 접속 방지 목적 |
| 인증 및 명령어 로그 | 서비스 이용 기간 | 보안 분석 및 관리자 조사 목적 |
| 서버 설정 값 | 서비스 이용 기간 | 봇 기능 유지 목적 |

## 3. 개인정보의 제3자 제공 및 위탁
본 시스템은 원칙적으로 정보주체의 개인정보를 수집·이용 목적으로 명시한 범위 내에서 처리하며, 다음의 경우를 제외하고는 정보주체의 사전 동의 없이는 본래의 사용목적을 초과하여 처리하거나 제3자에게 제공하지 않습니다.

* 정보주체로부터 별도의 동의를 받은 경우
* 서비스 이행을 위하여 필요한 경우

| 제공받는 자 | 제공받는 서비스 | 제공되는 개인정보 |
| :--- | :--- | :--- |
| Google (Gemini AI) | AI 기반 위험 분석 | 디스코드 사용자 ID, 계정 생성일, 이메일 주소, 기기 지문 정보 (분석 요청 시에만) |
| 서버 호스팅 업체 (IaaS) | 서비스 운영 및 데이터 저장 | 각종 설정 값, 암호화된 사용자 데이터 (저장소 제공) |

## 4. 정보주체와 법정대리인의 권리·의무 및 행사방법
정보주체는 법원에 대해 언제든지 다음 각 호의 개인정보 보호 관련 권리를 행사할 수 있습니다.

* 개인정보 열람 요구
* 오류 등이 있을 경우 정정 요구
* 삭제 요구 (Discord 서버 탈퇴 또는 관리자에게 요청)
* 처리정지 요구

## 5. 수집하는 개인정보 항목
본 시스템은 이용자에게 보다 편리한 서비스 이용을 위해 다음과 같이 개인정보를 수집하고 있습니다.

| 구분 | 수집 항목 | 비고 |
| :--- | :--- | :--- |
| **인증 시스템** | 사용자 디스코드 ID, 네이버 이메일 주소 (암호화), 기기 고유 식별자 (Fingerprint ID), Discord 계정 생성일 | 다중 계정 방지 목적으로만 이용 |
| **운영 정보** | 사용자가 전송한 명령어 로그, 서버 디스코드 ID, 봇에 관한 커스텀 설정 항목 | 봇 기능 유지 및 운영 분석 목적 |

## 6. 개인정보 파기 절차 및 방법
### 파기 절차
* 불필요한 개인정보 및 개인정보파일은 관계법령 및 내부방침 절차에 따라 안전하게 파기합니다.
### 파기 기한
* 개인정보는 보유 기간의 종료일(서버 탈퇴 후 7일)로부터 1일 이내에, 개인정보의 처리 목적 달성 등 그 개인정보가 불필요하게 되었을 때에는 5일 이내에 그 개인정보를 파기합니다.
### 파기 방법
* 전자적 형태의 정보 (DB 파일): 기록을 재생할 수 없는 기술적 방법을 사용하여 파기합니다.

## 7. 개인정보 안정성 확보 조치
* **개인정보의 암호화:** 민감 정보(이메일 주소)는 AES-256 암호화를 통해 안전하게 저장 및 관리됩니다.
* **접근 기록 보관:** 개인정보 처리 시스템에 접속한 기록(라우터 접속 기록, 데이터 서버 사용 기록)을 최소 1년 이상 보관·관리하고 있습니다.
* **접근 제한:** 개인정보를 처리하는 데이터베이스 시스템에 대한 접근 권한 부여·변경·말소를 통해 접근 통제 조치를 하고 있습니다.
* **폐쇄된 망에서의 사용:** 데이터 파일은 서버 내부망에만 존재하며, 외부 유출을 막기 위해 외부 연결이 차단된 환경에서 관리됩니다.

## 8. 개인정보 보호책임자 및 담당부서
본 시스템은 개인정보 관련 고충사항을 처리하기 위하여 아래와 같이 담당부서를 두고 개인정보 보호책임자 및 담당자를 지정하고 있습니다.

* **개인정보 보호책임자:** 서버 관리자
* **연락처:** Discord 서버 관리 채널 또는 DM 문의

## 9. 개인정보 처리방침 변경
이 개인정보 처리방침은 **2025년 09월 30일**부터 적용됩니다.
`;
    res.render('home.ejs', {
        title: '개인정보 보호정책',
        contentHtml: parser(privacyMarkdown)
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
    const { token, fingerprintId, email, fingerprintComponents } = req.body;
    const session = await db.get(`session_auth_${token}`);

    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.ip;
    let parsedComponents = {};
    try {
        if (fingerprintComponents) {
            parsedComponents = JSON.parse(fingerprintComponents);
        }
    } catch (e) {
        console.error('[FP LOG ERROR] 지문 컴포넌트 파싱 실패:', e);
    }

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
    session.fingerprintComponents = fingerprintComponents; // 컴포넌트 저장
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

        const existingEmailUserId = await db.get(`email_${guild.id}_${encryptedEmail}`);
        const existingFingerprintUserId = await db.get(`fingerprint_${guild.id}_${session.fingerprintId}`);

        const isReauthentication = (existingEmailUserId === member.id) || (existingFingerprintUserId === member.id);
        const isTrueDuplicate = (existingEmailUserId !== null && existingEmailUserId !== member.id) || 
                                (existingFingerprintUserId !== null && existingFingerprintUserId !== member.id);

        let finalVerdict; 
        if (isReauthentication) {
            finalVerdict = 'RE_AUTHENTICATION';
        } else if (isTrueDuplicate) {
            finalVerdict = 'TRUE_DUPLICATE';
        } else {
            finalVerdict = 'NEW_USER';
        }

        let emailSimilarityInfo = { isSimilar: false, matchedEmail: null, matchedUserId: null };
        if (!isTrueDuplicate && !existingEmailUserId) {
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

        const userData = {
            discordUser: { id: member.user.id, username: member.user.username, accountAgeInDays, publicFlags: member.user.flags.toArray(), hasAvatar: member.user.avatar !== null, hasBanner: member.user.banner !== null },
            discordMember: { guildId: guild.id },
            systemFootprint: { 
                isFingerprintDuplicate: isTrueDuplicate && existingFingerprintUserId !== null, 
                isEmailDuplicate: isTrueDuplicate && existingEmailUserId !== null, 
                isEmailSimilar: emailSimilarityInfo.isSimilar, 
                email: session.email,
                systemVerdict: finalVerdict
            }
        };

        if (finalVerdict === 'TRUE_DUPLICATE') {
            const reason = existingEmailUserId !== null ? 'email_duplicate' : 'fingerprint_duplicate';
            const logDetails = { email: session.email, fingerprintId: session.fingerprintId };
            
            if (existingEmailUserId !== null) logDetails.matchedUserId = existingEmailUserId;
            if (existingFingerprintUserId !== null) logDetails.matchedUserId = existingFingerprintUserId;

            await logAuthAttempt(guild.id, member.id, 'denied', reason, logDetails);
            
            try { await member.send('디스코드 서버 인증에 실패했습니다. 이미 다른 계정에서 사용 중인 이메일 또는 기기 정보입니다. 본계정으로 다시 시도해주세요.'); } catch (dmError) { console.error(`${member.user.tag}님에게 DM 전송 실패 (DENIED):`, dmError); }
            await member.kick('인증 실패: 중복된 이메일 또는 기기 정보 감지 (다중 계정 시도)').catch(kickError => console.error(`${member.user.tag}님을 추방하는데 실패했습니다 (DENIED):`, kickError));
            
            res.render('auth.ejs', { stage: 'error', error: '이미 다른 Discord 계정에서 사용 중인 이메일 또는 기기 정보입니다.', token: null });

            (async () => {
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

            const successMessage = finalVerdict === 'RE_AUTHENTICATION' 
                ? '성공적으로 재인증되어 역할이 부여되었습니다! (재가입)' 
                : '성공적으로 인증되어 역할이 부여되었습니다!';
            res.render('auth.ejs', { stage: 'success', message: successMessage, token: null, error: null });

            (async () => {
                const analysis = await getGeminiAnalysis(userData);
                
                const warningThresholds = ['매우 낮음', '낮음', '보통', '의심', '높음', '매우 높음'];
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
                
                let logType;
                let logReason;

                if (finalVerdict === 'RE_AUTHENTICATION') {
                    logType = 'allowed';
                    logReason = 're_authentication';
                }
                else if (warningThresholds.includes(analysis.riskLevel)) {
                    logType = 'warning';
                    logReason = `ai_risk:${analysis.riskLevel}`;
                } else {
                    logType = 'allowed';
                    logReason = 'success';
                }

                await logAuthAttempt(guild.id, member.id, logType, logReason, logDetails);
                await sendLogMessage(guild, logType, member, analysis, session, encryptedEmail);
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
        const rawVerifiedUsers = allData.filter(e => e.id.startsWith(`email_${guildId}_`)).map(e => ({ decryptedEmail: decrypt(e.id.substring(`email_${guildId}_`.length)), discordId: e.value }));
        const uniqueUsers = {};
        rawVerifiedUsers.forEach(user => {
            if (!uniqueUsers[user.discordId]) {
                uniqueUsers[user.discordId] = user;
            }
        });
        const verifiedUsers = Object.values(uniqueUsers);
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

        const textChannels = guild.channels.cache
            .filter(channel => channel.type === ChannelType.GuildText || channel.type === ChannelType.GuildNews)
            .map(channel => ({ id: channel.id, name: `#${channel.name}` }))
            .sort((a, b) => a.name.localeCompare(b.name));

        const roles = guild.roles.cache
            .filter(role => !role.managed && role.name !== '@everyone')
            .map(role => ({ id: role.id, name: role.name, color: role.hexColor }))
            .sort((a, b) => a.name.localeCompare(b.name));
        const currentSettings = {
            verifiedRoleId: await db.get(`config_verified_role_${guildId}`) || null,
            logRoleId: await db.get(`config_log_role_${guildId}`) || null,
            logThreadChannelId: await db.get(`config_log_thread_channel_${guildId}`) || null // NEW
        };
        res.render('dashboard_settings.ejs', {
            title: `${guild.name} - 설정`,
            guild,
            roles,
            textChannels,
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
    const { guildId, verifiedRoleId, logRoleId, logThreadChannelId } = req.body; // NEW: logThreadChannelId
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

        const oldChannelId = await db.get(`config_log_thread_channel_${guildId}`);
        let newChannelId = null;

        if (logThreadChannelId === 'default') {
            await db.delete(`config_log_thread_channel_${guildId}`);
            newChannelId = await db.get(`verification_channel_${guildId}`);
        } else {
            await db.set(`config_log_thread_channel_${guildId}`, logThreadChannelId);
            newChannelId = logThreadChannelId;
        }

        const verificationChannelId = await db.get(`verification_channel_${guildId}`);
        const finalChannelId = newChannelId || verificationChannelId;

        if (finalChannelId && oldChannelId !== finalChannelId) {
            const guild = await client.guilds.fetch(guildId);
            const channel = await guild.channels.fetch(finalChannelId);
            if (channel && channel.isTextBased()) {
                await createLogThreads(channel, null, guild.ownerId);
            }
        }

        res.redirect(`/dashboard/settings?guildId=${guildId}&success=true`);
    } catch (error) {
        console.error('[Save Settings] 오류:', error);
        res.status(500).send('설정 저장 중 오류가 발생했습니다.');
    }
});

async function sendLogMessage(guild, resultType, member, analysis, session, encryptedEmail) {
    try {
        let threadKey = resultType;
        if (resultType === 'allowed') {
            threadKey = 'success';
        } else if (resultType === 'denied') {
            threadKey = 'failure';
        }

        const logThreads = await db.get(`log_threads_${guild.id}`);
        if (!logThreads) return;

        const threadId = logThreads[threadKey];
        if (!threadId) return;

        const thread = await client.channels.fetch(threadId);
        if (!thread) return;
        if (thread.archived) {
            await thread.setArchived(false);
        }
        
        const logRoleId = await db.get(`config_log_role_${guild.id}`);
        let mentionContent = '';
        
        const decryptedEmail = decrypt(encryptedEmail);
        const embed = new EmbedBuilder()
            .setAuthor({ name: member.user.tag, iconURL: member.user.displayAvatarURL() })
            .setTimestamp()
            .setFooter({ text: `User ID: ${member.id}` });
        const components = [];
        
        // Embed 필드 구성
        if (resultType === 'success' || resultType === 'allowed') { // Success Log
            embed.setColor('Green').setTitle('✅ 인증 성공').addFields(
                { name: 'AI 위험도', value: `${analysis.riskLevel}`, inline: true },
                { name: 'AI 분석 요약', value: analysis.reasoning, inline: false },
                { name: '인증된 이메일', value: `\`${decryptedEmail}\``, inline: false },
                { name: '기기 식별자 (Fingerprint)', value: `\`${session.fingerprintId}\``, inline: false }
            );
        } else if (resultType === 'failure' || resultType === 'denied') { // Failure Log
            embed.setColor('Red').setTitle('🚨 인증 실패 (규칙 위반)').addFields(
                { name: 'AI 위험도', value: `${analysis.riskLevel}`, inline: true },
                { name: 'AI 분석 요약', value: analysis.reasoning, inline: false },
                { name: '시도한 이메일', value: `\`${session.email}\``, inline: false },
                { name: '기기 식별자 (Fingerprint)', value: `\`${session.fingerprintId}\``, inline: false }
            );
        } else if (resultType === 'warning') { // Warning Log
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
        
        // 3. 메시지 전송 (content 필드에 mentionContent 포함)
        await thread.send({ content: mentionContent, embeds: [embed], components: components });
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

                const alertSuffix = logRoleId ? ` 주요 알림은 ${mentionString} 역할 담당자분들께 전송됩니다.` : '';

                switch (type) {
                    case 'failure':
                        welcomeMessage = `🚨 **${mentionString}**, 이 스레드는 **인증 실패(차단)** 로그 채널입니다. 규칙 위반으로 차단된 사용자의 기록이 전송됩니다.${alertSuffix}`;
                        break;
                    case 'warning':
                        welcomeMessage = `⚠️ **${mentionString}**, 이 스레드는 **인증 경고(수동 확인)** 로그 채널입니다. AI가 잠재적 위험을 감지하여 관리자의 확인이 필요한 기록이 전송됩니다.${alertSuffix}`;
                        break;
                    case 'success':
                        welcomeMessage = `✅ **${mentionString}**, 이 스레드는 **인증 성공** 로그 채널입니다. 모든 성공 기록이 여기에 보관됩니다.${alertSuffix}`;
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
    console.log("[SCHEDULER] 세션 자동 정리 스케줄러가 시작되었습니다 (30분 간격).");
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
