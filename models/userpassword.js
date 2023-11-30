'use strict';

const {
  Model
} = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class UserPassword extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      UserPassword.belongsTo(models.User)
    }
  }
  UserPassword.init({
    owner_user_ID: DataTypes.INTEGER,
    URL: DataTypes.STRING,
    username: DataTypes.STRING,
    password: DataTypes.STRING,
    shared_by_user_ID: DataTypes.INTEGER,
    label: DataTypes.STRING
  }, {
    sequelize,
    modelName: 'UserPassword',
  });
  return UserPassword;
};