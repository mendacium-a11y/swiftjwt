import bcrypt from "bcrypt"

export const salt = async (password, rounds=10) => {
    const salt = await bcrypt.genSalt(rounds)
    const hashedPassword = bcrypt.hashSync(password, salt)

    return hashedPassword
}

export const checkPassword = (inputPassword, hashedPassword) => {
    return bcrypt.compareSync(inputPassword, hashedPassword)
}

