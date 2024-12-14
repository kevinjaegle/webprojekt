// Importieren der benötigten Module
const express = require('express'); // Express für den Server
const sqlite3 = require('sqlite3').verbose(); // SQLite für die Datenbank
const bodyParser = require('body-parser'); // Middleware zur Verarbeitung von Formulardaten
const session = require('express-session'); // Session-Management
const bcrypt = require('bcrypt'); // Passwort-Hashing
const fs = require('fs'); // Dateiverwaltung
const fastCsv = require('fast-csv'); // Für CSV-Exporte

// Initialisierung
const app = express();
const db = new sqlite3.Database('database.db'); // Verbindung zur Datenbank
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true })); // Verarbeiten von URL-encoded Daten
app.use(bodyParser.json()); // Verarbeiten von JSON-Daten
app.use(express.static(__dirname)); // Bereitstellen statischer Dateien wie HTML und CSS
app.use(session({
    secret: 'geheim', // Geheimschlüssel für Sessions
    resave: false,
    saveUninitialized: false,
}));

// Datenbank: Tabellen erstellen
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
`);
db.run(`
    CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT
    )
`);

// Middleware: Authentifizierung prüfen
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        res.status(401).send('Nicht autorisiert.');
        return;
    }
    next();
}

// Routen

// Hauptseite ausliefern
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// Registrierung
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // Passwort hashen

    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;
    db.run(query, [username, hashedPassword], (err) => {
        if (err) {
            console.error(err.message);
            res.status(400).send('Benutzername bereits vergeben.');
            return;
        }
        res.send('Registrierung erfolgreich!');
    });
});

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], async (err, user) => {
        if (err || !user || !(await bcrypt.compare(password, user.password))) {
            res.status(401).send('Ungültige Anmeldedaten.');
            return;
        }
        req.session.userId = user.id;
        res.send('Login erfolgreich!');
    });
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.send('Logout erfolgreich!');
    });
});

// Daten abrufen
app.get('/data', requireAuth, (req, res) => {
    const query = `SELECT * FROM entries`;
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error(err.message);
            res.status(500).send('Es gab einen Fehler beim Abrufen der Daten.');
            return;
        }
        res.json(rows); // Daten als JSON zurücksenden
    });
});

// Neue Daten speichern
app.post('/submit', requireAuth, (req, res) => {
    const { name, email } = req.body;
    const query = `INSERT INTO entries (name, email) VALUES (?, ?)`;

    db.run(query, [name, email], function (err) {
        if (err) {
            console.error(err.message);
            res.status(500).send('Es gab einen Fehler beim Speichern der Daten.');
            return;
        }
        res.send('Daten wurden erfolgreich gespeichert!');
        console.log(`Name: ${name}, E-Mail: ${email} gespeichert mit ID ${this.lastID}`);
    });
});

// Daten aktualisieren
app.post('/update', requireAuth, (req, res) => {
    const { id, name, email } = req.body;
    const query = `UPDATE entries SET name = ?, email = ? WHERE id = ?`;

    db.run(query, [name, email, id], function (err) {
        if (err) {
            console.error(err.message);
            res.status(500).send('Fehler beim Aktualisieren der Daten.');
            return;
        }
        res.send('Eintrag erfolgreich aktualisiert!');
    });
});

// Daten löschen
app.post('/delete', requireAuth, (req, res) => {
    const { id } = req.body;
    const query = `DELETE FROM entries WHERE id = ?`;

    db.run(query, [id], function (err) {
        if (err) {
            console.error(err.message);
            res.status(500).send('Fehler beim Löschen der Daten.');
            return;
        }
        res.send('Eintrag erfolgreich gelöscht!');
    });
});

// CSV-Export
app.get('/export', requireAuth, (req, res) => {
    const query = `SELECT * FROM entries`;
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error(err.message);
            res.status(500).send('Fehler beim Exportieren der Daten.');
            return;
        }

        const csvStream = fastCsv.format({ headers: true });
        const filePath = `${__dirname}/daten.csv`;

        const writableStream = fs.createWriteStream(filePath);
        writableStream.on('finish', () => {
            res.download(filePath, 'daten.csv', (err) => {
                if (err) {
                    console.error('Fehler beim Herunterladen:', err.message);
                }
                fs.unlinkSync(filePath); // Datei nach Download löschen
            });
        });

        csvStream.pipe(writableStream);
        rows.forEach((row) => csvStream.write(row));
        csvStream.end();
    });
});

// Server starten
app.listen(port, () => {
    console.log(`Server läuft auf http://localhost:${port}`);
});
