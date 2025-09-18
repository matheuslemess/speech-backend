// no novo arquivo de migration (ex: migrations/20250917100000_add_name_to_users_table.js)

exports.up = function(knex) {
  return knex.schema.table('users', (table) => {
    // Adiciona a coluna 'name' do tipo string, que não pode ser nula.
    table.string('name').notNullable();
  });
};

exports.down = function(knex) {
  return knex.schema.table('users', (table) => {
    // Remove a coluna 'name' se a migration for revertida.
    table.dropColumn('name');
  });
};