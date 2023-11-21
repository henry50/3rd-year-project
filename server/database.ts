import { Sequelize, Model, DataTypes } from "sequelize";

const database_uri = process.env.DATABASE_URI;
if(!database_uri){
    throw Error("DATABASE_URI must be set in .env");
}
export const sequelize = new Sequelize(database_uri);
try{
    await sequelize.authenticate();
    console.log("Connection successful");
} catch(error){
    throw new Error("Could not connect to database");
}

export class User extends Model {
    declare username: string;
    declare credentials: number[];
}

User.init({
    username: {
        type: DataTypes.STRING,
        allowNull: false
    },
    credentials: {
        type: DataTypes.JSON,
        allowNull: false
    }
}, { sequelize });

await sequelize.sync();
