import { Sequelize, Model, DataTypes } from "sequelize";
import dotenv from "dotenv";

dotenv.config();

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
    declare credentials: any;
}

User.init({
    username: {
        type: DataTypes.STRING,
        primaryKey: true
    },
    credentials: {
        type: DataTypes.JSON,
        allowNull: false
    }
}, { sequelize });

export class Expected extends Model {
    declare username: string;
    declare expected: number[];
}

Expected.init({
    username: {
        type: DataTypes.STRING,
        primaryKey: true
    },
    expected: {
        type: DataTypes.JSON,
        allowNull: false
    }
}, { sequelize });

await sequelize.sync();
