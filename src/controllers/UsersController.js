const { hash, compare } = require("bcrypt");
const AppError = require("../utils/AppError");

const sqliteConnection = require("../database/sqlite");

class UsersController {
    async create(request, response) {
        const { name, email, password } = request.body;

        const database = await sqliteConnection();
        const checkUserExist = await database.get("SELECT * FROM users WHERE email = (?)", [email])

        if (checkUserExist) {
            throw new AppError("Este e-mail já está em uso");
        }

        const hashedPassword = await hash(password, 8);

        await database.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]);

        return response.status(201).json();

    }

    async update(request, response) {
        const { name, email, password, oldpassword } = request.body;
        const { id } = request.params;

        const database = await sqliteConnection();
        const user = await database.get("SELECT * FROM users WHERE id = (?)", [id]);

        if (!user) {
            throw new AppError("Usuário não encontrado");
        }

        const userWithUpdateEmail = await database.get("SELECT * FROM users WHERE email = (?)", [email]);

        if (userWithUpdateEmail && userWithUpdateEmail.id !== user.id) {
            throw new AppError("E-mail já em uso.")
        }

        user.name = name ?? user.name;
        user.email = email ?? user.email;

        if (password && !oldpassword) {
            throw new AppError("Voce precisa informar a senha antiga para definir a nova senha");
        }

 
        if (password && oldpassword) {
            const checkOldPassword = await compare(oldpassword, user.password);

            if (!checkOldPassword) {
                throw new AppError("A Senha antiga não confere.");
            }

            user.password = await hash(password, 8);
        }

        await database.run(`
        UPDATE users SET
        name = ?,
        email = ?,
        password = ?,
        updated_at = DATETIME('now')
        WHERE id = ?`,
            [user.name, user.email, user.password, id]
        );

        return response.status(200).json();

    }
}


module.exports = UsersController;