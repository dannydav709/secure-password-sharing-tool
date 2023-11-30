Example of how to generate miagration and model files using sequelize:

```shell
npx sequelize-cli model:generate --name UserPassword --attributes owner_user_ID:integer,URL:string,username:string,password:string,shared_by_user_ID:integer
```

Running the new migration:
```shell
npx sequelize-cli db:migrate
```

Undo migration
```shell
npx sequelize-cli db:migrate:undo
```