require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // Para criptografar senhas
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
// deixarei alguns comentários durante o código, pois ele não será feito só por mim, então para os outros alunos ficarem cientes do que cada coisa faz e o que eu estou fazendo. 
// Middleware
app.use(bodyParser.json());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type'],
}));

// Conexão com o MongoDB
const mongoURI = process.env.MONGO_URI;
mongoose.connect(mongoURI)
    .then(() => console.log('Conectado ao MongoDB Atlas'))
    .catch(err => console.error('Erro ao conectar ao MongoDB:', err));

// Modelos
const ItemSchema = new mongoose.Schema({
    name: { type: String, required: true },
});
const Item = mongoose.model('Item', ItemSchema);

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    senha: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema);

// Rota de Cadastro de Usuário
app.post('/usuarios', async (req, res) => {
    const { email, senha } = req.body;

    try {
        // Verifica se o e-mail já existe
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'E-mail já cadastrado' });
        }

        // Criptografa a senha
        const hashedSenha = await bcrypt.hash(senha, 10);

        // Cria um novo usuário
        const newUser = new User({ email, senha: hashedSenha });
        const savedUser = await newUser.save();
        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', user: savedUser });
    } catch (err) {
        res.status(500).json({ message: 'Erro ao cadastrar usuário', error: err.message });
    }
});

// **Rota de Login**: Para fazer login com e-mail e senha
app.post('/login', async (req, res) => {
    const { email, senha } = req.body;

    console.log('Email:', email);
    console.log('Senha:', senha);

    try {
        // Verifica se o usuário existe
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado' });
        }

        // Compara a senha fornecida com a senha criptografada no banco de dados
        const isMatch = await bcrypt.compare(senha, user.senha);
        if (!isMatch) {
            return res.status(401).json({ message: 'Senha incorreta' });
        }

        // Gera um token JWT (com validade de 1 hora, por exemplo)
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Retorna o token e informações do usuário
        res.status(200).json({
            message: 'Login bem-sucedido',
            token, // O token gerado
            userId: user._id,
            email: user.email,
        });
    } catch (err) {
        console.error('Erro ao realizar login:', err); // Log de erro
        res.status(500).json({ message: 'Erro ao realizar login', error: err.message });
    }
});

// Outras rotas (usuarios, itens) permanecem as mesmas...

// Rota para buscar todos os usuários (sem a senha)
app.get('/usuarios', async (req, res) => {
    try {
        const users = await User.find({}, '-senha'); // Exclui o campo senha
        res.status(200).json(users);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao buscar usuários', error: err.message });
    }
});

// Rota para editar usuários (permitindo alteração de e-mail e senha)
app.put('/usuarios/:id', async (req, res) => {
    const { email, senha } = req.body;

    try {
        const hashedSenha = senha ? await bcrypt.hash(senha, 10) : undefined;

        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            { email, ...(senha && { senha: hashedSenha }) },
            { new: true }
        );
        if (!updatedUser) {
            return res.status(404).json({ message: 'Usuário não encontrado' });
        }
        res.status(200).json(updatedUser);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao atualizar usuário', error: err.message });
    }
});

// Rota para excluir usuários
app.delete('/usuarios/:id', async (req, res) => {
    try {
        const deletedUser = await User.findByIdAndDelete(req.params.id);
        if (!deletedUser) {
            return res.status(404).json({ message: 'Usuário não encontrado' });
        }
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ message: 'Erro ao excluir usuário', error: err.message });
    }
});

// Rota para criação de itens
app.post('/items', async (req, res) => {
    const { name } = req.body;

    try {
        if (!name) {
            return res.status(400).json({ message: 'O campo "name" é obrigatório' });
        }

        const newItem = new Item({ name });
        const savedItem = await newItem.save();
        res.status(201).json(savedItem);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao salvar item', error: err.message });
    }
});

// Rota para listar todos os itens
app.get('/items', async (req, res) => {
    try {
        const items = await Item.find();
        res.status(200).json(items);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao buscar itens', error: err.message });
    }
});

// Rota para editar itens
app.put('/items/:id', async (req, res) => {
    try {
        const updatedItem = await Item.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!updatedItem) {
            return res.status(404).json({ message: 'Item não encontrado' });
        }
        res.status(200).json(updatedItem);
    } catch (err) {
        res.status(500).json({ message: 'Erro ao atualizar item', error: err.message });
    }
});

// Rota para excluir itens
app.delete('/items/:id', async (req, res) => {
    try {
        const deletedItem = await Item.findByIdAndDelete(req.params.id);
        if (!deletedItem) {
            return res.status(404).json({ message: 'Item não encontrado' });
        }
        res.status(204).send();
    } catch (err) {
        res.status(500).json({ message: 'Erro ao excluir item', error: err.message });
    }
});

// Inicia o servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});
