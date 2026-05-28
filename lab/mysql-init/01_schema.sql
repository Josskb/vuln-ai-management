-- MediConnect lab database — fictitious medical data
CREATE TABLE IF NOT EXISTS patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nom VARCHAR(100),
    prenom VARCHAR(100),
    dossier_medical TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO patients (nom, prenom, dossier_medical) VALUES
('Dupont', 'Marie', 'Allergie pénicilline — antécédents cardiaques'),
('Martin', 'Jean', 'Diabète type 2 — insuline quotidienne'),
('Bernard', 'Sophie', 'Grossesse 6 mois — suivi obstétrique');
