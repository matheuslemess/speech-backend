const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const knexConfig = require('./knexfile').development;
const knex = require('knex')(knexConfig);

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'SEGREDO_SUPER_SECRETO_MUDE_DEPOIS';

app.use(cors());
app.use(express.json());

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.sendStatus(401);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// --- ROTAS DE AUTENTICAÇÃO ---

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Nome, email e senha são obrigatórios.' });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const [userId] = await knex('users').insert({ name, email, password_hash });

    res.status(201).json({ id: userId, name, email });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT') {
        return res.status(409).json({ message: 'Este email já está em uso.' });
    }
    res.status(500).json({ message: 'Erro ao registrar usuário.', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
        }

        const user = await knex('users').where({ email }).first();
        if (!user) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordCorrect) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }
        
        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao fazer login.', error: error.message });
    }
});

// --- ROTAS DE USUÁRIO ---

app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const user = await knex('users').where({ id: req.user.userId }).first();
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }
        res.status(200).json({ id: user.id, name: user.name, email: user.email });
    } catch (error) {
        res.status(500).json({ message: "Erro ao buscar dados do usuário.", error: error.message });
    }
});

app.put('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const { name, email, newPassword, currentPassword } = req.body;

        if (!currentPassword) {
            return res.status(400).json({ message: 'A senha atual é obrigatória para salvar as alterações.' });
        }

        const user = await knex('users').where({ id: req.user.userId }).first();
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        const isPasswordCorrect = await bcrypt.compare(currentPassword, user.password_hash);
        if (!isPasswordCorrect) {
            return res.status(403).json({ message: 'A senha atual está incorreta.' });
        }

        const updates = {};
        if (name) updates.name = name;

        if (email && email !== user.email) {
            const existingUser = await knex('users').where({ email }).first();
            if (existingUser) {
                return res.status(409).json({ message: 'Este email já está em uso por outra conta.' });
            }
            updates.email = email;
        }

        if (newPassword) {
            updates.password_hash = await bcrypt.hash(newPassword, 10);
        }
        
        if (Object.keys(updates).length > 0) {
            await knex('users').where({ id: user.id }).update(updates);
        }

        res.status(200).json({ message: 'Perfil atualizado com sucesso!' });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao atualizar o perfil.', error: error.message });
    }
});

// --- ROTAS DE DISCURSOS ---

app.get('/api/speeches', authenticateToken, async (req, res) => {
    try {
        const speeches = await knex('speeches').where({ user_id: req.user.userId });
        res.status(200).json(speeches);
    } catch (error) {
        res.status(500).json({ message: "Erro ao buscar discursos.", error: error.message });
    }
});

app.post('/api/speeches', authenticateToken, async (req, res) => {
    try {
        const { title, content } = req.body;
        if (!title || !content) {
            return res.status(400).json({ message: "Título e conteúdo são obrigatórios." });
        }
        const [newSpeech] = await knex('speeches')
            .insert({ title, content, user_id: req.user.userId })
            .returning('*');
        res.status(201).json(newSpeech);
    } catch (error) {
        res.status(500).json({ message: "Erro ao criar discurso.", error: error.message });
    }
});

app.get('/api/speeches/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const speech = await knex('speeches')
            .where({ id: id, user_id: req.user.userId })
            .first();
        if (!speech) {
            return res.status(404).json({ message: "Discurso não encontrado ou não autorizado." });
        }
        res.status(200).json(speech);
    } catch (error) {
        res.status(500).json({ message: "Erro ao buscar discurso.", error: error.message });
    }
});

app.put('/api/speeches/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content } = req.body;
        if (!title || !content) {
            return res.status(400).json({ message: "Título e conteúdo são obrigatórios." });
        }
        const count = await knex('speeches')
            .where({ id: id, user_id: req.user.userId })
            .update({ title, content, updated_at: knex.fn.now() });
        if (count === 0) {
            return res.status(404).json({ message: "Discurso não encontrado ou não autorizado para edição." });
        }
        const updatedSpeech = await knex('speeches').where({ id: id }).first();
        res.status(200).json(updatedSpeech);
    } catch (error) {
        res.status(500).json({ message: "Erro ao atualizar discurso.", error: error.message });
    }
});

app.delete('/api/speeches/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const count = await knex('speeches')
            .where({ id: id, user_id: req.user.userId })
            .del();
        if (count === 0) {
            return res.status(404).json({ message: "Discurso não encontrado ou não autorizado." });
        }
        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ message: "Erro ao deletar discurso.", error: error.message });
    }
});

// --- INICIALIZAÇÃO DO SERVIDOR ---

const startServer = async () => {
  try {
    console.log('Rodando as migrations...');
    await knex.migrate.latest();
    console.log('Migrations concluídas com sucesso.');

    app.listen(PORT, () => {
      console.log(`🚀 Servidor rodando na porta ${PORT}`);
    });
  } catch (error) {
    console.error("❌ Erro ao rodar migrations ou iniciar o servidor:", error);
    process.exit(1);
  }
};

startServer();