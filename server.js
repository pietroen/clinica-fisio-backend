
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const PDFDocument = require("pdfkit");

const app = express();
const db = new sqlite3.Database("db.sqlite");
const SECRET = "segredo_supersecreto";

app.use(cors({ origin: "*" }));
app.use(bodyParser.json());

db.run(`CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT,
  email TEXT UNIQUE,
  senha TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS pacientes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT,
  idade INTEGER,
  sexo TEXT,
  telefone TEXT,
  email TEXT,
  historico TEXT,
  usuario_id INTEGER
)`);

app.post("/registrar", (req, res) => {
  const { nome, email, senha } = req.body;
  const hash = bcrypt.hashSync(senha, 8);
  db.run("INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)", [nome, email, hash], function (err) {
    if (err) return res.status(400).json({ erro: "Email já existe" });
    res.json({ id: this.lastID });
  });
});

app.post("/login", (req, res) => {
  const { email, senha } = req.body;
  db.get("SELECT * FROM usuarios WHERE email = ?", [email], (err, user) => {
    if (!user || !bcrypt.compareSync(senha, user.senha)) {
      return res.status(401).json({ erro: "Credenciais inválidas" });
    }
    const token = jwt.sign({ id: user.id, nome: user.nome }, SECRET, { expiresIn: "1d" });
    res.json({ token, nome: user.nome });
  });
});

function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ erro: "Token não fornecido" });
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ erro: "Token inválido" });
  }
}

app.post("/esqueci-senha", (req, res) => {
  const { email } = req.body;
  db.get("SELECT * FROM usuarios WHERE email = ?", [email], (err, user) => {
    if (!user) return res.status(404).json({ erro: "E-mail não encontrado" });
    res.json({ mensagem: "E-mail de recuperação enviado (simulado)." });
  });
});

app.get("/pacientes", auth, (req, res) => {
  db.all("SELECT * FROM pacientes WHERE usuario_id = ?", [req.user.id], (err, rows) => {
    res.json(rows);
  });
});

app.post("/pacientes", auth, (req, res) => {
  const { nome, idade, sexo, telefone, email, historico } = req.body;
  db.run(
    "INSERT INTO pacientes (nome, idade, sexo, telefone, email, historico, usuario_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [nome, idade, sexo, telefone, email, historico, req.user.id],
    function (err) {
      if (err) return res.status(500).json({ erro: err.message });
      res.json({ id: this.lastID });
    }
  );
});

app.get("/pacientes/:id/pdf", auth, (req, res) => {
  const id = req.params.id;
  db.get("SELECT * FROM pacientes WHERE id = ? AND usuario_id = ?", [id, req.user.id], (err, p) => {
    if (!p) return res.status(404).json({ erro: "Paciente não encontrado" });

    const doc = new PDFDocument();
    res.setHeader("Content-Type", "application/pdf");
    doc.pipe(res);
    doc.fontSize(18).text("Prontuário do Paciente", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`Nome: ${p.nome}`);
    doc.text(`Idade: ${p.idade}`);
    doc.text(`Sexo: ${p.sexo}`);
    doc.text(`Telefone: ${p.telefone}`);
    doc.text(`E-mail: ${p.email}`);
    doc.moveDown().text("Histórico:");
    doc.text(p.historico);
    doc.end();
  });
});

app.listen(3000, () => {
  console.log("API rodando em http://localhost:3000");
});
