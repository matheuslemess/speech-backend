// index.js (versão final do backend)

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Configuração do Knex
const knexConfig = require('./knexfile').development;
const knex = require('knex')(knexConfig);

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'SEGREDO_SUPER_SECRETO_MUDE_DEPOIS';


app.use(cors());
app.use(express.json());

// --- MIDDLEWARE DE AUTENTICAÇÃO ---
// Esta função vai rodar antes das rotas protegidas
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"

    if (token == null) {
        return res.sendStatus(401); // Unauthorized
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Forbidden
        }
        req.user = user; // Adiciona os dados do usuário (ex: { userId: 1, email: '...' }) na requisição
        next(); // Passa para a próxima função (a rota em si)
    });
};


// --- ROTAS PÚBLICAS (AUTENTICAÇÃO) ---

app.post('/api/auth/register', async (req, res) => { /* ...código de antes, sem alteração... */ 
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const [userId] = await knex('users').insert({ email, password_hash });
    res.status(201).json({ id: userId, email });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT') {
        return res.status(409).json({ message: 'Este email já está em uso.' });
    }
    res.status(500).json({ message: 'Erro ao registrar usuário.', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
    console.log('--- Nova Tentativa de Login ---'); // Log inicial
    try {
        const { email, password } = req.body;
        console.log('Email recebido para login:', email); // Log do email

        if (!email || !password) {
            console.log('Erro: Email ou senha não fornecidos.');
            return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
        }

        const user = await knex('users').where({ email }).first();

        // ESTE É O LOG MAIS IMPORTANTE:
        console.log('Usuário encontrado no banco de dados:', user); 

        if (!user) {
            console.log('Login falhou: Nenhum usuário encontrado com esse email.');
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        console.log('Usuário encontrado. Comparando a senha...');
        const isPasswordCorrect = await bcrypt.compare(password, user.password_hash);
        
        console.log('Resultado da comparação de senha:', isPasswordCorrect); // Log do resultado do bcrypt

        if (!isPasswordCorrect) {
            console.log('Login falhou: A senha está incorreta.');
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }
        
        console.log('Login bem-sucedido! Gerando token...');
        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });

    } catch (error) {
        console.error('ERRO GERAL NA ROTA DE LOGIN:', error); // Log de erro completo
        res.status(500).json({ message: 'Erro ao fazer login.', error: error.message });
    }
});

// ROTA PARA BUSCAR DADOS DO USUÁRIO LOGADO
app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const user = await knex('users').where({ id: req.user.userId }).first();

        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        // Nunca retorne o password_hash! Apenas os dados seguros.
        res.status(200).json({
            id: user.id,
            email: user.email
        });

    } catch (error) {
        res.status(500).json({ message: "Erro ao buscar dados do usuário.", error: error.message });
    }
});

// ROTA PARA ATUALIZAR DADOS DO USUÁRIO LOGADO
app.put('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const { email, newPassword, currentPassword } = req.body;

        // 1. Validação: A senha atual é obrigatória para qualquer alteração.
        if (!currentPassword) {
            return res.status(400).json({ message: 'A senha atual é obrigatória para salvar as alterações.' });
        }

        const user = await knex('users').where({ id: req.user.userId }).first();
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        // 2. Verificar se a senha atual está correta
        const isPasswordCorrect = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isPasswordCorrect) {
            return res.status(403).json({ message: 'A senha atual está incorreta.' });
        }

        const updates = {};

        // 3. Se um novo email foi fornecido, prepara a atualização
        if (email && email !== user.email) {
            const existingUser = await knex('users').where({ email }).first();
            if (existingUser) {
                return res.status(409).json({ message: 'Este email já está em uso por outra conta.' });
            }
            updates.email = email;
        }

        // 4. Se uma nova senha foi fornecida, prepara a atualização
        if (newPassword) {
            updates.password_hash = await bcrypt.hash(newPassword, 10);
        }
        
        // 5. Se houver atualizações a fazer, executa no banco
        if (Object.keys(updates).length > 0) {
            await knex('users').where({ id: user.id }).update(updates);
        }

        res.status(200).json({ message: 'Perfil atualizado com sucesso!' });

    } catch (error) {
        console.error("Erro ao atualizar perfil:", error);
        res.status(500).json({ message: 'Erro ao atualizar o perfil.', error: error.message });
    }
});

// --- ROTAS PROTEGIDAS (DISCURSOS) ---
// Note o `authenticateToken` antes da lógica da rota

// Listar todos os discursos do usuário logado
app.get('/api/speeches', authenticateToken, async (req, res) => {
    try {
        const speeches = await knex('speeches').where({ user_id: req.user.userId });
        res.status(200).json(speeches);
    } catch (error) {
        res.status(500).json({ message: "Erro ao buscar discursos.", error: error.message });
    }
});

// Criar um novo discurso
app.post('/api/speeches', authenticateToken, async (req, res) => {
    try {
        const { title, content } = req.body;
        if (!title || !content) {
            return res.status(400).json({ message: "Título e conteúdo são obrigatórios." });
        }

        const [newSpeech] = await knex('speeches')
            .insert({ title, content, user_id: req.user.userId })
            .returning('*'); // Retorna o objeto criado
            
        res.status(201).json(newSpeech);
    } catch (error) {
        res.status(500).json({ message: "Erro ao criar discurso.", error: error.message });
    }
});

// Buscar um único discurso pelo ID
app.get('/api/speeches/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params; // Pega o ID da URL (ex: /api/speeches/5)

        const speech = await knex('speeches')
            .where({ id: id, user_id: req.user.userId }) // Garante que o usuário só pode ver o que é seu
            .first(); // .first() para pegar apenas um resultado

        if (!speech) {
            return res.status(404).json({ message: "Discurso não encontrado ou não autorizado." });
        }

        res.status(200).json(speech);
    } catch (error) {
        res.status(500).json({ message: "Erro ao buscar discurso.", error: error.message });
    }
});

// Atualizar (Editar) um discurso existente
app.put('/api/speeches/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content } = req.body;

        // Validação simples
        if (!title || !content) {
            return res.status(400).json({ message: "Título e conteúdo são obrigatórios." });
        }

        // O método .update() do Knex para editar o registro
        const count = await knex('speeches')
            .where({ id: id, user_id: req.user.userId }) // Garante que o usuário só pode editar o que é seu
            .update({
                title: title,
                content: content,
                updated_at: knex.fn.now() // Atualiza o timestamp
            });

        if (count === 0) {
            return res.status(404).json({ message: "Discurso não encontrado ou não autorizado para edição." });
        }

        // Opcional: retornar o discurso atualizado
        const updatedSpeech = await knex('speeches').where({ id: id }).first();
        res.status(200).json(updatedSpeech);

    } catch (error) {
        res.status(500).json({ message: "Erro ao atualizar discurso.", error: error.message });
    }
});

// (Opcional, mas bom ter) Deletar um discurso
app.delete('/api/speeches/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const count = await knex('speeches')
            .where({ id: id, user_id: req.user.userId }) // Garante que o usuário só pode deletar o que é dele
            .del();

        if (count === 0) {
            return res.status(404).json({ message: "Discurso não encontrado ou não autorizado." });
        }

        res.sendStatus(204); // No Content (sucesso, sem corpo de resposta)
    } catch (error) {
        res.status(500).json({ message: "Erro ao deletar discurso.", error: error.message });
    }
});


app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta http://localhost:${PORT}`);
});

// --- INICIA O SERVIDOR E RODA AS MIGRAÇÕES (SUBSTITUA SEU app.listen POR ISSO) ---

const startServer = async () => {
  try {
    console.log('Rodando as migrations...');
    await knex.migrate.latest(); // Knex vai usar a configuração de 'production' automaticamente na Render
    console.log('Migrations concluídas com sucesso.');

    app.listen(PORT, () => {
      console.log(`🚀 Servidor rodando na porta ${PORT}`);
    });

  } catch (error) {
    console.error("❌ Erro ao rodar migrations ou iniciar o servidor:", error);
    process.exit(1); // Encerra o processo com erro se as migrations falharem
  }
};

startServer();