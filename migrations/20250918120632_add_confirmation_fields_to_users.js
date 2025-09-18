// dentro do novo arquivo em /migrations

exports.up = function(knex) {
  return knex.schema.table('users', function(table) {
    // Status do usuário: PENDING_CONFIRMATION ou ACTIVE
    table.string('status').defaultTo('PENDING_CONFIRMATION');
    
    // Token para confirmar o e-mail
    table.string('confirmationToken').nullable();
    
    // Data de expiração do token
    table.bigInteger('tokenExpiry').nullable();
  });
};

exports.down = function(knex) {
  return knex.schema.table('users', function(table) {
    table.dropColumn('status');
    table.dropColumn('confirmationToken');
    table.dropColumn('tokenExpiry');
  });
};