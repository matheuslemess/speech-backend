// Em knexfile.js
module.exports = {
  development: {
    client: 'sqlite3',
    connection: {
      filename: './database.db' // Continua o mesmo para desenvolvimento
    },
    useNullAsDefault: true,
    migrations: {
      directory: './migrations'
    }
  },

  // Adicione esta nova configuração para produção
  production: {
    client: 'pg', // Usaremos o cliente 'pg'
    connection: process.env.DATABASE_URL, // Puxa a URL do banco das variáveis de ambiente
    migrations: {
      directory: './migrations'
    }
  }
};