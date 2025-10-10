import jwt from "jsonwebtoken";

export const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      return res.status(401).json({ msg: "Acceso denegado: faltan credenciales" });
    }

    // El formato correcto es "Bearer <token>"
    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ msg: "Token no proporcionado" });
    }

    // Verificar token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "supersecretkey");
    req.user = decoded; // Guardamos info del usuario

    next(); // Continúa hacia la ruta
  } catch (error) {
    console.error("Error JWT:", error.message);
    return res.status(403).json({ msg: "Token inválido o expirado" });
  }
};
