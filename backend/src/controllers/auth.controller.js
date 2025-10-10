import User from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    const user = new User({ username, email, password: hashed });
    await user.save();

    res.json({ msg: "Usuario registrado con éxito" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: "Usuario no encontrado" });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(401).json({ msg: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

/**
 * Logout (stateless): simplemente responder. 
 * El frontend debe eliminar el token (o si usas httpOnly cookie, borrarla aquí).
 */
export const logout = async (req, res) => {
  res.json({ msg: "Logout exitoso (el cliente debe eliminar el token)" });
};