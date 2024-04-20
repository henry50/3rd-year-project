import dotenv from "dotenv";
import { DataTypes, Model, Sequelize } from "sequelize";

dotenv.config();

const databaseURI = process.env.DATABASE_URI;
if (!databaseURI) {
    throw Error("DATABASE_URI must be set in .env");
}
export const sequelize = new Sequelize(databaseURI);
try {
    await sequelize.authenticate();
    console.log("Connection successful");
} catch (error) {
    throw new Error("Could not connect to database");
}

export class User extends Model {
    declare username: string;
    declare credentials: any;
}

User.init(
    {
        username: {
            type: DataTypes.STRING,
            primaryKey: true,
        },
        credentials: {
            type: DataTypes.JSON,
            allowNull: false,
        },
    },
    { sequelize },
);

export class TempValues extends Model {
    declare username: string;
    declare values: any;
}

TempValues.init(
    {
        username: {
            type: DataTypes.STRING,
            primaryKey: true,
        },
        values: {
            type: DataTypes.JSON,
            allowNull: false,
        },
    },
    { sequelize },
);

await sequelize.sync();
