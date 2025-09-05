const express = require('express');
const path = require('path');
const { 
    default: makeWASocket, 
    DisconnectReason, 
    useMultiFileAuthState,
    fetchLatestBaileysVersion 
} = require('@whiskeysockets/baileys');
const { Boom } = require('@hapi/boom');
const crypto = require('crypto');
const fs = require('fs');
const P = require('pino');
const cors = require('cors');

// ==================== CONFIGURAÇÕES ====================
const config = {
    // Configurações dinâmicas (podem ser alteradas via frontend)
    groupId: process.env.GROUP_ID || '120363421874776025@g.us',
    adminNumber: process.env.ADMIN_NUMBER || '559189204297@c.us',
    
    // Mensagens
    welcomeMessage: 'Bem-vindo ao GRUPO VIP - AUTOGIRO! 🎉\nVocê agora tem acesso ao conteúdo exclusivo.',
    
    // Hubla
    hubla: {
        webhookSecret: process.env.HUBLA_WEBHOOK_SECRET || 'SEU_HUBLA_WEBHOOK_SECRET',
        sendExpirationWarnings: true
    },

    // MODERAÇÃO
    moderation: {
        badWords: ['golpe', 'fraude', 'pix', 'dinheiro fácil', 'milionário', 'vagas', 'oportunidade','picareta','golpista','salafrario','pessoa ruim','sem alma','bixo ruim','gordo','pançudo','leilão', 'carro ruim', 'sem margem'],
        blockedLinkHosts: ['bit.ly', 'cutt.ly', 'goo.gl', 'tinyurl.com', 'linktr.ee'],
        warnMessage: 'Olá! A sua mensagem foi removida porque contém conteúdo não permitido. Por favor, evite compartilhar links externos ou palavras associadas a spam para manter a segurança do grupo.',
    },

    // Rate Limiting
    rateLimiting: {
        minDelay: 3000,
        maxRetries: 3,
        retryDelay: 5000
    }
};

// ==================== ARMAZENAMENTO EM MEMÓRIA ====================
const members = new Map();
const logs = [];

// Estatísticas
const stats = {
    totalMembers: 0,
    activeMembersAdded: 0,
    membersRemoved: 0,
    webhooksReceived: 0,
    messagesDeleted: 0,
    usersWarned: 0,
    spamBlocked: 0,
    startTime: Date.now()
};

// ==================== VARIÁVEIS GLOBAIS ====================
let sock;
let whatsappReady = false;
let currentQRCode = null;

// ==================== CLASSE RATE LIMITER ====================
class RateLimiter {
    constructor() {
        this.queue = [];
        this.processing = false;
        this.lastAction = 0;
        this.minDelay = config.rateLimiting.minDelay;
    }
    
    async execute(action) {
        return new Promise((resolve, reject) => {
            this.queue.push({ action, resolve, reject });
            this.processQueue();
        });
    }
    
    async processQueue() {
        if (this.processing || this.queue.length === 0) return;
        
        this.processing = true;
        
        while (this.queue.length > 0) {
            const { action, resolve, reject } = this.queue.shift();
            
            try {
                const now = Date.now();
                const timeSinceLastAction = now - this.lastAction;
                if (timeSinceLastAction < this.minDelay) {
                    await new Promise(r => setTimeout(r, this.minDelay - timeSinceLastAction));
                }
                
                const result = await action();
                this.lastAction = Date.now();
                resolve(result);
                
            } catch (error) {
                reject(error);
            }
        }
        
        this.processing = false;
    }
}

const rateLimiter = new RateLimiter();

// ==================== FUNÇÕES DE CONFIGURAÇÃO ====================
function saveConfig() {
    try {
        if (!fs.existsSync('./data')) {
            fs.mkdirSync('./data');
        }
        
        const configData = {
            groupId: config.groupId,
            adminNumber: config.adminNumber,
            welcomeMessage: config.welcomeMessage,
            updatedAt: new Date()
        };
        
        fs.writeFileSync('./data/config.json', JSON.stringify(configData, null, 2));
        addLog('CONFIG_SAVED', 'Configurações salvas');
    } catch (error) {
        console.error('❌ Erro ao salvar configurações:', error);
        addLog('ERRO_CONFIG', `Erro ao salvar configurações: ${error.message}`);
    }
}

function loadConfig() {
    try {
        if (fs.existsSync('./data/config.json')) {
            const data = JSON.parse(fs.readFileSync('./data/config.json', 'utf8'));
            config.groupId = data.groupId || config.groupId;
            config.adminNumber = data.adminNumber || config.adminNumber;
            config.welcomeMessage = data.welcomeMessage || config.welcomeMessage;
            console.log('📋 Configurações carregadas do arquivo');
        }
    } catch (error) {
        console.error('❌ Erro ao carregar configurações:', error);
    }
}

// ==================== FUNÇÕES DE UTILIDADE ====================

// Formatar telefone com validação brasileira
function formatPhone(phone) {
    if (!phone) return null;
    
    let cleanPhone = phone.replace(/\D/g, '');
    
    if (cleanPhone.length === 11 && cleanPhone.startsWith('0')) {
        cleanPhone = '55' + cleanPhone.substring(1);
    } else if (cleanPhone.length === 10) {
        cleanPhone = '55' + cleanPhone;
    } else if (cleanPhone.length === 11 && !cleanPhone.startsWith('55')) {
        cleanPhone = '55' + cleanPhone;
    }
    
    if (cleanPhone.length < 12 || cleanPhone.length > 13) {
        return null;
    }
    
    if (!cleanPhone.startsWith('55')) {
        return null;
    }
    
    return `${cleanPhone}@s.whatsapp.net`;
}

function formatGroupId(groupId) {
    return groupId.includes('@g.us') ? groupId : `${groupId}@g.us`;
}

function validateHublaWebhook(payload, signature) {
    if (!signature || !config.hubla.webhookSecret || config.hubla.webhookSecret === 'SEU_HUBLA_WEBHOOK_SECRET') {
        return false;
    }
    
    const hash = crypto.createHmac('sha256', config.hubla.webhookSecret)
        .update(payload)
        .digest('hex');
    return `sha256=${hash}` === signature;
}

// Sistema de persistência de dados
function loadMembers() {
    try {
        if (fs.existsSync('./data/members.json')) {
            const data = JSON.parse(fs.readFileSync('./data/members.json', 'utf8'));
            for (const [phone, memberData] of Object.entries(data)) {
                memberData.expiresAt = new Date(memberData.expiresAt);
                memberData.addedAt = new Date(memberData.addedAt);
                members.set(phone, memberData);
            }
            stats.totalMembers = members.size;
            console.log(`📚 ${members.size} membros carregados do arquivo`);
        } else {
            if (!fs.existsSync('./data')) {
                fs.mkdirSync('./data');
            }
        }
    } catch (error) {
        console.error('❌ Erro ao carregar membros:', error);
    }
}

function saveMembers() {
    try {
        if (!fs.existsSync('./data')) {
            fs.mkdirSync('./data');
        }
        
        const data = Object.fromEntries(members);
        fs.writeFileSync('./data/members.json', JSON.stringify(data, null, 2));
        addLog('SISTEMA', 'Membros salvos no arquivo');
    } catch (error) {
        console.error('❌ Erro ao salvar membros:', error);
        addLog('ERRO_SISTEMA', `Erro ao salvar membros: ${error.message}`);
    }
}

function addLog(action, details) {
    const log = {
        timestamp: new Date(),
        action,
        details
    };
    logs.push(log);
    console.log(`📝 [${log.timestamp.toLocaleString('pt-BR')}] ${action}: ${details}`);
    
    if (logs.length > 100) {
        logs.shift();
    }
}

// Adicionar membro ao grupo com retry
async function addMemberToGroup(phone, name, retries = 0) {
    return rateLimiter.execute(async () => {
        try {
            if (!whatsappReady || !sock) {
                throw new Error('WhatsApp não está conectado');
            }
            
            const groupJid = formatGroupId(config.groupId);
            
            try {
                const groupMetadata = await sock.groupMetadata(groupJid);
                const isAlreadyMember = groupMetadata.participants.some(p => p.id === phone);
                
                if (isAlreadyMember) {
                    addLog('MEMBRO_JA_EXISTE', `${name} (${phone}) já está no grupo`);
                    return true;
                }
            } catch (error) {
                addLog('ERRO_VERIFICAR_GRUPO', `Erro ao verificar grupo: ${error.message}`);
            }
            
            const result = await sock.groupParticipantsUpdate(groupJid, [phone], 'add');
            
            if (result && result[0] && result[0].status !== '200') {
                throw new Error(`Falha ao adicionar: ${result[0].status}`);
            }
            
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            const welcomeMsg = `${config.welcomeMessage}\n\nOlá ${name}! 👋`;
            await sock.sendMessage(groupJid, { text: welcomeMsg });
            
            addLog('MEMBRO_ADICIONADO', `${name} (${phone})`);
            stats.activeMembersAdded++;
            
            saveMembers();
            
            await notifyAdmin(`✅ *Novo membro adicionado*\n\nNome: ${name}\nTelefone: ${phone}\nPlataforma: Hubla`);
            
            return true;
            
        } catch (error) {
            if (retries < config.rateLimiting.maxRetries) {
                addLog('RETRY_ADICIONAR', `Tentativa ${retries + 1} para ${name}: ${error.message}`);
                await new Promise(resolve => setTimeout(resolve, config.rateLimiting.retryDelay));
                return addMemberToGroup(phone, name, retries + 1);
            }
            
            addLog('ERRO_ADICIONAR', `${name} (${phone}): ${error.message}`);
            console.error('❌ Erro ao adicionar membro:', error);
            return false;
        }
    });
}

// Remover membro do grupo com retry
async function removeMemberFromGroup(phone, name, reason = 'Assinatura expirada', retries = 0) {
    return rateLimiter.execute(async () => {
        try {
            if (!whatsappReady || !sock) {
                throw new Error('WhatsApp não está conectado');
            }
            
            const groupJid = formatGroupId(config.groupId);
            
            const result = await sock.groupParticipantsUpdate(groupJid, [phone], 'remove');
            
            if (result && result[0] && result[0].status !== '200') {
                throw new Error(`Falha ao remover: ${result[0].status}`);
            }
            
            addLog('MEMBRO_REMOVIDO', `${name} (${phone}): ${reason}`);
            stats.membersRemoved++;
            
            saveMembers();
            
            await notifyAdmin(`❌ *Membro removido*\n\nNome: ${name}\nTelefone: ${phone}\nMotivo: ${reason}`);
            
            return true;
            
        } catch (error) {
            if (retries < config.rateLimiting.maxRetries) {
                addLog('RETRY_REMOVER', `Tentativa ${retries + 1} para ${name}: ${error.message}`);
                await new Promise(resolve => setTimeout(resolve, config.rateLimiting.retryDelay));
                return removeMemberFromGroup(phone, name, reason, retries + 1);
            }
            
            addLog('ERRO_REMOVER', `${name} (${phone}): ${error.message}`);
            console.error('❌ Erro ao remover membro:', error);
            return false;
        }
    });
}

// Notificar admin
async function notifyAdmin(message) {
    return rateLimiter.execute(async () => {
        try {
            if (whatsappReady && sock && config.adminNumber) {
                await sock.sendMessage(config.adminNumber, { 
                    text: `🤖 *Sistema Hubla*\n\n${message}` 
                });
                return true;
            }
            return false;
        } catch (error) {
            console.error('❌ Erro ao notificar admin:', error);
            return false;
        }
    });
}

// ==================== WHATSAPP BAILEYS ====================
async function startWhatsApp() {
    try {
        const { version, isLatest } = await fetchLatestBaileysVersion();
        console.log(`🔄 Usando Baileys v${version.join('.')}, isLatest: ${isLatest}`);
        
        const { state, saveCreds } = await useMultiFileAuthState('./auth_info_baileys');
        
        sock = makeWASocket({
            version,
            logger: P({ level: 'silent' }),
            auth: state,
            defaultQueryTimeoutMs: 60000,
            connectTimeoutMs: 60000,
            keepAliveIntervalMs: 30000,
        });
        
        sock.ev.on('connection.update', (update) => {
            const { connection, lastDisconnect, qr } = update;
            
            if (qr) {
                console.log('📱 QR Code gerado! Acesse o painel web para escanear');
                
                currentQRCode = qr;
                addLog('QR_CODE_GERADO', 'QR Code disponível no painel web');
                
                try {
                    const QRCode = require('qrcode-terminal');
                    QRCode.generate(qr, { small: true });
                } catch (error) {
                    console.log('💡 QR Code disponível no painel web');
                }
                
                console.log('👆 QR Code também disponível no painel web');
            }
            
            if (connection === 'close') {
                whatsappReady = false;
                currentQRCode = null;
                const shouldReconnect = (lastDisconnect?.error instanceof Boom)?.output?.statusCode !== DisconnectReason.loggedOut;
                console.log('❌ Conexão fechada devido a:', lastDisconnect?.error);
                addLog('WHATSAPP_DESCONECTADO', lastDisconnect?.error?.message || 'Motivo desconhecido');
                
                if (shouldReconnect) {
                    console.log('🔄 Reconectando em 10 segundos...');
                    setTimeout(startWhatsApp, 10000);
                } else {
                    console.log('❌ Deslogado. Escaneie o QR novamente.');
                    addLog('WHATSAPP_LOGOUT', 'Necessário escanear QR novamente');
                }
            } else if (connection === 'open') {
                console.log('✅ WhatsApp conectado com sucesso!');
                whatsappReady = true;
                currentQRCode = null;
                addLog('WHATSAPP_CONECTADO', 'Conexão estabelecida');
                checkGroup();
            }
        });
        
        sock.ev.on('creds.update', saveCreds);
        
        // ==================== SISTEMA DE MODERAÇÃO CORRIGIDO ====================
        sock.ev.on('messages.upsert', async (m) => {
            const msg = m.messages[0];
            
            if (!msg || msg.key.fromMe || !msg.message) return;
            
            const isGroup = msg.key.remoteJid.endsWith('@g.us');
            
            // Verificar se a mensagem é do grupo configurado (sempre usar config atual)
            const currentGroupId = formatGroupId(config.groupId);
            const isFromGroup = msg.key.remoteJid === currentGroupId;
            
            // Log para debug da moderação
            console.log(`📨 Mensagem recebida:`);
            console.log(`   Grupo: ${isGroup ? 'Sim' : 'Não'}`);
            console.log(`   ID da mensagem: ${msg.key.remoteJid}`);
            console.log(`   Grupo configurado: ${currentGroupId}`);
            console.log(`   É do grupo certo: ${isFromGroup ? 'Sim' : 'Não'}`);
            
            if (!isGroup || !isFromGroup) {
                console.log(`❌ Mensagem ignorada - não é do grupo monitorado`);
                return;
            }
            
            let textMessage = msg.message?.extendedTextMessage?.text || 
                            msg.message?.conversation || 
                            msg.message?.imageMessage?.caption || 
                            msg.message?.videoMessage?.caption || '';
            
            if (!textMessage) {
                console.log(`ℹ️ Mensagem sem texto - ignorada`);
                return;
            }
            
            const originalText = textMessage;
            textMessage = textMessage.toLowerCase();
            
            console.log(`📝 Analisando mensagem: "${originalText.substring(0, 50)}..."`);
            
            let shouldDelete = false;
            let reason = '';

            // Verificar palavras proibidas
            const foundBadWord = config.moderation.badWords.find(word => 
                textMessage.includes(word.toLowerCase())
            );
            
            if (foundBadWord) {
                shouldDelete = true;
                reason = `Palavra proibida encontrada: ${foundBadWord}`;
                console.log(`🚫 Palavra proibida detectada: ${foundBadWord}`);
            }
            
            // Verificar links
            if (!shouldDelete) {
                const urlRegex = /(https?:\/\/[^\s]+)/g;
                const foundLinks = textMessage.match(urlRegex);
                
                if (foundLinks) {
                    console.log(`🔗 Links encontrados: ${foundLinks.join(', ')}`);
                    
                    const isBlocked = foundLinks.some(url => {
                        return config.moderation.blockedLinkHosts.some(host => 
                            url.toLowerCase().includes(host.toLowerCase())
                        );
                    });
                    
                    if (isBlocked) {
                        shouldDelete = true;
                        reason = `Link externo não permitido encontrado`;
                        console.log(`🚫 Link bloqueado detectado`);
                    }
                }
            }

            if (shouldDelete) {
                console.log(`🗑️ Removendo mensagem: ${reason}`);
                
                try {
                    // Deletar a mensagem para todos
                    await sock.sendMessage(msg.key.remoteJid, {
                        delete: {
                            remoteJid: msg.key.remoteJid,
                            fromMe: false,
                            id: msg.key.id,
                            participant: msg.key.participant
                        }
                    });
                    
                    console.log(`✅ Mensagem removida com sucesso`);
                    
                    // Aguardar antes de enviar aviso
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    
                    // Notificar o usuário no privado
                    if (msg.key.participant) {
                        try {
                            await sock.sendMessage(msg.key.participant, { 
                                text: config.moderation.warnMessage 
                            });
                            console.log(`📨 Aviso enviado para ${msg.key.participant}`);
                        } catch (warnError) {
                            console.log(`❌ Erro ao enviar aviso: ${warnError.message}`);
                        }
                    }

                    addLog('MENSAGEM_REMOVIDA', `Mensagem de ${msg.key.participant} removida. Motivo: ${reason}`);
                    stats.messagesDeleted++;
                    stats.usersWarned++;
                    stats.spamBlocked++;
                    
                } catch (error) {
                    console.log(`❌ Erro ao remover mensagem: ${error.message}`);
                    addLog('ERRO_REMOVER_MSG', `Não foi possível remover mensagem de ${msg.key.participant}. Erro: ${error.message}`);
                }
            } else {
                console.log(`✅ Mensagem aprovada`);
            }
        });
        
    } catch (error) {
        console.error('❌ Erro ao inicializar WhatsApp:', error);
        addLog('ERRO_INICIALIZACAO', error.message);
        setTimeout(startWhatsApp, 15000);
    }
}

async function checkGroup() {
    try {
        const groupJid = formatGroupId(config.groupId);
        const groupMetadata = await sock.groupMetadata(groupJid);
        console.log(`📋 Grupo encontrado: ${groupMetadata.subject}`);
        console.log(`👥 Participantes: ${groupMetadata.participants.length}`);
        console.log(`🛡️ Moderação ativa para: ${groupMetadata.subject}`);
        addLog('GRUPO_VERIFICADO', `${groupMetadata.subject} - ${groupMetadata.participants.length} participantes - Moderação ativa`);
    } catch (error) {
        console.error('❌ Erro ao verificar grupo:', error.message);
        addLog('ERRO_GRUPO', `Erro ao verificar grupo: ${error.message}`);
    }
}

// ==================== EXPRESS APP ====================
const app = express();

// Middlewares
app.use(cors());
app.use('/webhook/hubla', express.raw({ type: 'application/json' }));
app.use(express.json());

// Middleware de segurança
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

// Servir arquivos estáticos do frontend
app.use(express.static(path.join(__dirname, 'public')));

// Rota para servir o frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== WEBHOOK HUBLA ====================
app.post('/webhook/hubla', async (req, res) => {
    try {
        const signature = req.headers['hubla-signature'] || req.headers['x-hubla-signature'];
        const payload = req.body;
        
        stats.webhooksReceived++;
        
        if (!validateHublaWebhook(payload, signature)) {
            addLog('WEBHOOK_INVALID', 'Assinatura inválida ou secret não configurado');
            return res.status(401).send('Assinatura inválida');
        }
        
        const data = JSON.parse(payload);
        const { type, event } = data;
        
        addLog('WEBHOOK_RECEBIDO', `Evento: ${type}`);
        
        if (type === 'subscription.activated') {
            const user = event.user;
            const subscription = event.subscription;
            const phone = formatPhone(user.phone);
            const name = `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'Cliente';
            const email = user.email || '';
            const subscriptionId = subscription.id;
            const credits = subscription.credits || 30;
            
            if (!phone) {
                addLog('ERRO_TELEFONE', `Telefone inválido para ${name}: ${user.phone}`);
                return res.status(400).json({ error: 'Telefone inválido' });
            }
            
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + credits);
            
            members.set(phone, {
                name,
                email,
                expiresAt,
                subscriptionId,
                credits,
                status: 'active',
                addedAt: new Date()
            });
            
            stats.totalMembers = members.size;
            
            const success = await addMemberToGroup(phone, name);
            
            if (success) {
                addLog('ASSINATURA_ATIVADA', `${name} - ${credits} créditos - Expira em: ${expiresAt.toLocaleDateString('pt-BR')}`);
            }
        }
        
        else if (type === 'subscription.expiring') {
            const user = event.user;
            const subscription = event.subscription;
            const phone = formatPhone(user.phone);
            const name = `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'Cliente';
            const credits = subscription.credits || 0;
            
            addLog('ASSINATURA_EXPIRANDO', `${name} - Restam ${credits} créditos`);
            
            await notifyAdmin(`⚠️ *Assinatura expirando*\n\nNome: ${name}\nTelefone: ${phone}\nCréditos restantes: ${credits}`);
            
            if (config.hubla.sendExpirationWarnings && phone) {
                try {
                    if (whatsappReady && sock) {
                        const warningMsg = `⚠️ Olá ${name}!\n\nSua assinatura está expirando. Restam apenas ${credits} créditos.\n\nRenove para continuar tendo acesso ao grupo VIP!`;
                        await rateLimiter.execute(async () => {
                            await sock.sendMessage(phone, { text: warningMsg });
                        });
                        addLog('AVISO_ENVIADO', `Aviso de expiração enviado para ${name}`);
                    }
                } catch (error) {
                    addLog('ERRO_AVISO', `Erro ao enviar aviso para ${name}: ${error.message}`);
                }
            }
        }
        
        else if (type === 'subscription.deactivated') {
            const user = event.user;
            const subscription = event.subscription;
            const phone = formatPhone(user.phone);
            const name = `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'Cliente';
            const subscriptionId = subscription.id;
            
            if (phone && members.has(phone)) {
                members.delete(phone);
                stats.totalMembers = members.size;
                
                await removeMemberFromGroup(phone, name, 'Assinatura desativada - créditos esgotados');
                
                addLog('ASSINATURA_DESATIVADA', `${name} removido - ID: ${subscriptionId}`);
            }
        }
        
        res.status(200).json({ success: true, type });
        
    } catch (error) {
        console.error('❌ Erro no webhook Hubla:', error);
        addLog('WEBHOOK_ERRO', error.message);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// ==================== API ENDPOINTS ====================

app.get('/api/status', (req, res) => {
    res.json({
        whatsappConnected: whatsappReady,
        totalMembers: members.size,
        stats: {
            ...stats,
            uptime: Math.floor((Date.now() - stats.startTime) / 1000 / 60)
        },
        groupId: config.groupId,
        webhookConfigured: config.hubla.webhookSecret !== 'SEU_HUBLA_WEBHOOK_SECRET',
        timestamp: new Date().toISOString()
    });
});

app.get('/api/members', (req, res) => {
    const membersList = Array.from(members.entries()).map(([phone, data]) => ({
        phone,
        name: data.name,
        email: data.email,
        expiresAt: data.expiresAt,
        credits: data.credits,
        status: data.status,
        addedAt: data.addedAt,
        daysRemaining: Math.ceil((new Date(data.expiresAt) - new Date()) / (1000 * 60 * 60 * 24))
    }));
    
    res.json(membersList);
});

app.get('/api/logs', (req, res) => {
    res.json(logs.slice(-50));
});

// Endpoint para QR Code
app.get('/api/qrcode', (req, res) => {
    res.json({
        qrCode: currentQRCode,
        hasQRCode: !!currentQRCode,
        whatsappConnected: whatsappReady
    });
});

// Endpoint para obter configurações
app.get('/api/config', (req, res) => {
    res.json({
        groupId: config.groupId,
        adminNumber: config.adminNumber,
        welcomeMessage: config.welcomeMessage,
        whatsappConnected: whatsappReady
    });
});

// Endpoint para atualizar configurações (CORRIGIDO)
app.post('/api/config', (req, res) => {
    try {
        const { groupId, adminNumber, welcomeMessage } = req.body;
        
        const oldGroupId = config.groupId;
        
        if (groupId) {
            config.groupId = groupId.includes('@g.us') ? groupId : `${groupId}@g.us`;
        }
        
        if (adminNumber) {
            config.adminNumber = adminNumber.includes('@c.us') ? adminNumber : `${adminNumber}@c.us`;
        }
        
        if (welcomeMessage) {
            config.welcomeMessage = welcomeMessage;
        }
        
        // Se mudou o grupo, atualizar logs
        if (oldGroupId !== config.groupId) {
            addLog('GRUPO_ALTERADO', `Grupo alterado de ${oldGroupId} para ${config.groupId}`);
            console.log(`🔄 Grupo alterado para: ${config.groupId}`);
            
            // Verificar novo grupo se WhatsApp estiver conectado
            if (whatsappReady && sock) {
                setTimeout(checkGroup, 2000);
            }
        }
        
        saveConfig();
        addLog('CONFIG_UPDATED', `Grupo: ${config.groupId}, Admin: ${config.adminNumber}`);
        
        res.json({
            success: true,
            message: 'Configurações atualizadas com sucesso',
            config: {
                groupId: config.groupId,
                adminNumber: config.adminNumber,
                welcomeMessage: config.welcomeMessage
            },
            groupChanged: oldGroupId !== config.groupId
        });
        
    } catch (error) {
        console.error('❌ Erro ao atualizar configurações:', error);
        res.status(500).json({ error: 'Erro ao atualizar configurações' });
    }
});

// Endpoint para listar grupos disponíveis (CORRIGIDO)
app.get('/api/groups', async (req, res) => {
    try {
        if (!whatsappReady || !sock) {
            return res.status(400).json({ 
                error: 'WhatsApp não está conectado',
                connected: false 
            });
        }
        
        addLog('BUSCANDO_GRUPOS', 'Iniciando busca por grupos...');
        
        let groupsList = [];
        
        try {
            // Buscar grupos via groupFetchAllParticipating
            console.log('🔍 Buscando grupos...');
            const groups = await sock.groupFetchAllParticipating();
            
            console.log(`📋 Encontrados ${Object.keys(groups || {}).length} grupos`);
            
            if (groups && Object.keys(groups).length > 0) {
                for (const [groupId, groupData] of Object.entries(groups)) {
                    try {
                        // Verificar se é admin
                        const myJid = sock.user?.id;
                        let isAdmin = false;
                        
                        if (myJid && groupData.participants) {
                            isAdmin = groupData.participants.some(participant => {
                                const participantId = participant.id || participant.jid;
                                return participantId === myJid && 
                                       (participant.admin === 'admin' || participant.admin === 'superadmin');
                            });
                        }
                        
                        const groupInfo = {
                            id: groupId,
                            name: groupData.subject || 'Grupo sem nome',
                            participants: groupData.participants ? groupData.participants.length : 0,
                            isAdmin: isAdmin,
                            description: groupData.desc || ''
                        };
                        
                        groupsList.push(groupInfo);
                        console.log(`📱 ${groupInfo.name} (${groupInfo.participants} membros) - Admin: ${isAdmin ? 'SIM' : 'NÃO'}`);
                        
                    } catch (err) {
                        console.log(`Erro ao processar grupo ${groupId}:`, err.message);
                    }
                }
            }
        } catch (error) {
            console.log('Método groupFetchAllParticipating falhou:', error.message);
            
            // Fallback: mostrar pelo menos o grupo configurado
            if (config.groupId) {
                try {
                    const groupMetadata = await sock.groupMetadata(config.groupId);
                    const myJid = sock.user?.id;
                    
                    let isAdmin = false;
                    if (myJid && groupMetadata.participants) {
                        isAdmin = groupMetadata.participants.some(p => 
                            p.id === myJid && (p.admin === 'admin' || p.admin === 'superadmin')
                        );
                    }
                    
                    groupsList.push({
                        id: config.groupId,
                        name: groupMetadata.subject || 'Grupo Atual',
                        participants: groupMetadata.participants ? groupMetadata.participants.length : 0,
                        isAdmin: isAdmin,
                        description: 'Grupo atualmente configurado no sistema'
                    });
                    
                    addLog('GRUPO_ATUAL_ADICIONADO', `Grupo atual adicionado: ${groupMetadata.subject}`);
                } catch (err) {
                    console.log('Erro ao buscar grupo atual:', err.message);
                }
            }
        }
        
        // Filtrar apenas grupos onde é admin
        const adminGroups = groupsList.filter(group => group.isAdmin);
        
        addLog('GRUPOS_ENCONTRADOS', `${groupsList.length} grupos total, ${adminGroups.length} onde é admin`);
        
        // Se não encontrou nenhum grupo onde é admin, mostrar todos
        const finalGroups = adminGroups.length > 0 ? adminGroups : groupsList;
        
        res.json({
            success: true,
            total: groupsList.length,
            adminGroups: adminGroups.length,
            groups: finalGroups.sort((a, b) => a.name.localeCompare(b.name))
        });
        
    } catch (error) {
        console.error('❌ Erro geral ao listar grupos:', error);
        addLog('ERRO_LISTAR_GRUPOS', error.message);
        
        // Fallback final
        const fallbackGroups = [];
        if (config.groupId) {
            fallbackGroups.push({
                id: config.groupId,
                name: 'Grupo Configurado',
                participants: 0,
                isAdmin: true,
                description: 'Grupo atual do sistema'
            });
        }
        
        res.json({
            success: false,
            error: 'Erro ao buscar grupos',
            groups: fallbackGroups,
            fallback: true
        });
    }
});

// ==================== ENDPOINTS DE DEBUG E TESTE ====================

// Endpoint para testar moderação
app.post('/api/test-moderation', async (req, res) => {
    try {
        if (!whatsappReady || !sock) {
            return res.status(400).json({ error: 'WhatsApp não está conectado' });
        }
        
        const { message } = req.body;
        
        if (!message) {
            return res.status(400).json({ error: 'Mensagem é obrigatória' });
        }
        
        const groupJid = formatGroupId(config.groupId);
        
        // Enviar mensagem de teste no grupo
        await sock.sendMessage(groupJid, { 
            text: `🧪 TESTE DE MODERAÇÃO: ${message}\n\n(Esta é uma mensagem de teste do sistema)` 
        });
        
        addLog('TESTE_MODERACAO', `Mensagem de teste enviada: ${message}`);
        
        res.json({
            success: true,
            message: 'Mensagem de teste enviada',
            groupId: config.groupId,
            testMessage: message
        });
        
    } catch (error) {
        console.error('❌ Erro no teste de moderação:', error);
        res.status(500).json({ error: 'Erro ao enviar mensagem de teste' });
    }
});

// Endpoint para debug da moderação
app.get('/api/debug/moderation', (req, res) => {
    res.json({
        moderationConfig: config.moderation,
        currentGroupId: config.groupId,
        whatsappReady,
        stats: {
            messagesDeleted: stats.messagesDeleted,
            usersWarned: stats.usersWarned,
            spamBlocked: stats.spamBlocked
        }
    });
});

// Endpoint para debug do WhatsApp
app.get('/api/debug/whatsapp', async (req, res) => {
    try {
        const debug = {
            whatsappReady,
            sockExists: !!sock,
            userInfo: sock?.user || null,
            configGroupId: config.groupId,
            timestamp: new Date().toISOString()
        };
        
        if (whatsappReady && sock) {
            try {
                const groups = await sock.groupFetchAllParticipating();
                debug.groupsCount = Object.keys(groups || {}).length;
                debug.groupsMethod = 'groupFetchAllParticipating';
            } catch (error) {
                debug.groupsError = error.message;
            }
            
            if (config.groupId) {
                try {
                    const groupMeta = await sock.groupMetadata(config.groupId);
                    debug.currentGroup = {
                        id: groupMeta.id,
                        name: groupMeta.subject,
                        participants: groupMeta.participants.length
                    };
                } catch (error) {
                    debug.currentGroupError = error.message;
                }
            }
        }
        
        res.json(debug);
        
    } catch (error) {
        res.status(500).json({
            error: error.message,
            whatsappReady,
            sockExists: !!sock
        });
    }
});

// ==================== VERIFICAÇÕES PERIÓDICAS ====================

// Verificar membros expirados a cada 6 horas
setInterval(async () => {
    const now = new Date();
    let expiredMembers = [];
    
    for (const [phone, memberData] of members.entries()) {
        if (memberData.status === 'active' && new Date(memberData.expiresAt) <= now) {
            expiredMembers.push({ phone, ...memberData });
        }
    }
    
    for (const member of expiredMembers) {
        members.delete(member.phone);
        stats.totalMembers = members.size;
        
        await removeMemberFromGroup(member.phone, member.name, 'Assinatura expirada automaticamente');
        addLog('EXPIRAÇÃO_AUTOMÁTICA', `${member.name} removido automaticamente`);
    }
    
    if (expiredMembers.length > 0) {
        saveMembers();
        await notifyAdmin(`🔄 *Limpeza automática*\n\n${expiredMembers.length} membros com assinatura expirada foram removidos automaticamente.`);
    }
    
}, 6 * 60 * 60 * 1000);

// Relatório automático a cada 12 horas
setInterval(async () => {
    const now = new Date();
    let activeCount = 0;
    let expiringSoon = 0;
    let expiredCount = 0;
    
    for (const [phone, memberData] of members.entries()) {
        if (memberData.status === 'active') {
            const daysToExpire = Math.ceil((new Date(memberData.expiresAt) - now) / (1000 * 60 * 60 * 24));
            
            if (daysToExpire <= 0) {
                expiredCount++;
            } else if (daysToExpire <= 3) {
                expiringSoon++;
                activeCount++;
            } else {
                activeCount++;
            }
        }
    }
    
    if (activeCount > 0 || expiredCount > 0) {
        const report = `📊 *Relatório automático*\n\n👥 Membros ativos: ${activeCount}\n⚠️ Expirando em 3 dias: ${expiringSoon}\n❌ Expirados: ${expiredCount}\n\n🤖 Uptime: ${Math.floor((Date.now() - stats.startTime) / 1000 / 60)} minutos`;
        await notifyAdmin(report);
    }
    
    addLog('RELATORIO_AUTOMATICO', `${activeCount} ativos, ${expiringSoon} expirando, ${expiredCount} expirados`);
    
}, 12 * 60 * 60 * 1000);

// ==================== INICIALIZAÇÃO ====================

const PORT = process.env.PORT || 3001;

loadConfig();
loadMembers();

app.listen(PORT, () => {
    console.log('🚀 SISTEMA HUBLA + WHATSAPP INICIADO');
    console.log('=====================================');
    console.log(`🌐 Sistema rodando em: http://localhost:${PORT}`);
    console.log(`📡 Webhook URL: http://localhost:${PORT}/webhook/hubla`);
    console.log(`📊 API Status: http://localhost:${PORT}/api/status`);
    console.log(`🎯 Grupo: ${config.groupId}`);
    console.log(`🛡️ Moderação ativa`);
    console.log('=====================================');
    console.log('🧪 Para testar moderação:');
    console.log('   POST /api/test-moderation');
    console.log('   GET /api/debug/moderation');
    console.log('=====================================');
    
    addLog('SISTEMA_INICIADO', `Sistema rodando na porta ${PORT} - Moderação ativa`);
});

startWhatsApp();

setInterval(saveMembers, 5 * 60 * 1000);
setInterval(saveConfig, 10 * 60 * 1000);

setInterval(() => {
    if (logs.length > 200) {
        logs.splice(0, 100);
        addLog('SISTEMA', 'Logs antigos removidos');
    }
}, 24 * 60 * 60 * 1000);

// Tratamento de erros
process.on('unhandledRejection', (error) => {
    console.error('❌ Erro não tratado:', error);
    addLog('ERRO_SISTEMA', `Erro não tratado: ${error.message}`);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Exceção não capturada:', error);
    addLog('ERRO_SISTEMA', `Exceção não capturada: ${error.message}`);
});

process.on('SIGINT', async () => {
    console.log('\n🛑 Parando sistema...');
    console.log(`📊 Estatísticas finais:`);
    console.log(`   👥 Total de membros: ${stats.totalMembers}`);
    console.log(`   ✅ Membros adicionados: ${stats.activeMembersAdded}`);
    console.log(`   ❌ Membros removidos: ${stats.membersRemoved}`);
    console.log(`   📡 Webhooks recebidos: ${stats.webhooksReceived}`);
    console.log(`   🗑️ Mensagens removidas: ${stats.messagesDeleted}`);
    console.log(`   🚫 Spam bloqueado: ${stats.spamBlocked}`);
    
    saveMembers();
    saveConfig();
    addLog('SISTEMA_PARADO', 'Sistema encerrado pelo usuário');
    
    if (sock) {
        sock.end();
    }
    
    process.exit(0);
});

module.exports = { 
    sock, 
    members, 
    stats, 
    addLog, 
    formatPhone, 
    addMemberToGroup, 
    removeMemberFromGroup 
};
