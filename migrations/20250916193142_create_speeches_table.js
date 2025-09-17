exports.up = function(knex) {
  return knex.schema.createTable('speeches', (table) => {
    table.increments('id').primary();
    table.string('title').notNullable();
    table.text('content').notNullable();

    // Chave estrangeira: linkando o discurso ao usuário
    table.integer('user_id')
      .unsigned()
      .notNullable()
      .references('id')
      .inTable('users')
      .onDelete('CASCADE'); // Se o usuário for deletado, seus discursos também serão.

    table.timestamps(true, true); // Adiciona created_at e updated_at
  });
};

exports.down = function(knex) {
  return knex.schema.dropTable('speeches');
};