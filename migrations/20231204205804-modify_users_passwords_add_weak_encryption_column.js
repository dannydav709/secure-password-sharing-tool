'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    await queryInterface.addColumn(
        'UserPasswords',
        'weak_encryption',
        {
          type: Sequelize.BOOLEAN,
          allowNull: false,
          defaultValue: false
        }
    );
    await queryInterface.addColumn(
        'UserPasswords',
        'id_of_original_password',
        {
            type: Sequelize.INTEGER,
            defaultValue: null
        }
    )
  },

  async down (queryInterface, Sequelize) {
    await queryInterface.removeColumn(
        'UserPasswords',
        'weak_encryption'
    );
    await queryInterface.removeColumn(
        'UserPasswords',
        'id_of_original_password'
    );
  }
};
