import express from "express";
import User from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { authMiddleware } from "../middleware/auth.js"; 

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";



// Registro
router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Hashear contraseña
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Crear usuario
    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });

    const savedUser = await newUser.save();
    res.status(201).json(savedUser);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error en el registro de usuario" });
  }
});

// 🔑 LOGIN
// ---------------------------
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validar datos
    if (!email || !password) {
      return res.status(400).json({ error: "Email y contraseña son obligatorios" });
    }

    // Buscar usuario
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    // Verificar contraseña
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Contraseña incorrecta" });
    }

    // Crear token JWT
    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Inicio de sesión exitoso",
      token,
      user: { id: user._id, username: user.username, email: user.email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al iniciar sesión" });
  }
});


// 🚪 LOGOUT (simulado)

router.post("/logout", authMiddleware, async (req, res) => {
  try {
    // En proyectos simples, el logout se maneja desde el frontend eliminando el token
    res.status(200).json({ message: "Sesión cerrada correctamente" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al cerrar sesión" });
  }
});

export default router;

console.log("✅ auth.routes.js cargado correctamente");


// ✅ Ruta protegida para probar el middleware
router.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ msg: "Usuario no encontrado" });
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error al obtener usuario" });
  }
});
