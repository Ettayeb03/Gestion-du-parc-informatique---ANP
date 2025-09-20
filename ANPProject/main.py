import MySQLdb
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_login import current_user
from flask_mysqldb import MySQL
from MySQLdb.cursors import DictCursor
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pandas as pd
import os
from werkzeug.utils import secure_filename
from io import BytesIO


app = Flask(__name__)
app.secret_key = 'cle-secrete-pour-session'

app.config.update(
    MYSQL_HOST='localhost',
    MYSQL_USER='root',
    MYSQL_PASSWORD='',
    MYSQL_DB='parc_informatique'
)

mysql = MySQL(app)

# Décorateurs

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if session.get('role') != 'admin':
            return "Accès refusé", 403
        return f(*args, **kwargs)
    return wrapped

# Utilitaires

def get_cursor(dict_cursor=True):
    return mysql.connection.cursor(DictCursor if dict_cursor else None)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def enregistrer_historique(utilisateur, action, cible, cible_id, description):
    """
    Enregistre une action dans la table historique.
    """
    cur = get_cursor()
    try:
        cur.execute("""
            INSERT INTO historique (utilisateur, action, cible, cible_id, description, date_action)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            utilisateur,
            action,
            cible,
            cible_id,
            description,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # format compatible MySQL DATETIME
        ))
        mysql.connection.commit()
    except Exception as e:
        print("❌ Erreur lors de l’enregistrement de l’historique :", e)
        mysql.connection.rollback()
    finally:
        cur.close()

def get_employes():
    cur = get_cursor()
    try:
        cur.execute("SELECT id, nom, prenom FROM employes ORDER BY nom")
        return cur.fetchall()
    finally:
        cur.close()

def get_services():
    cur = get_cursor()
    try:
        cur.execute("SELECT id, nom FROM services ORDER BY nom")
        return cur.fetchall()
    finally:
        cur.close()

def get_employe_info(employe_id):
    cur = get_cursor()
    try:
        cur.execute("SELECT * FROM employes WHERE id = %s", (employe_id,))
        return cur.fetchone()
    finally:
        cur.close()

def get_service_info(service_id):
    cur = get_cursor()
    try:
        cur.execute("SELECT * FROM services WHERE id = %s", (service_id,))
        return cur.fetchone()
    finally:
        cur.close()

def get_materiel_info(materiel_id):
    cur = get_cursor()
    try:
        cur.execute("SELECT * FROM materiels WHERE id = %s", (materiel_id,))
        return cur.fetchone()
    finally:
        cur.close()

# Création admin par défaut

@app.before_request
def ajouter_admin_par_defaut():
    try:
        cur = get_cursor()
        # Vérifie si l'utilisateur 'admin' existe
        cur.execute("SELECT * FROM utilisateurs WHERE username = %s", ('admin',))
        admin = cur.fetchone()

        # Vérifie si l'utilisateur 'Tayeb' existe
        cur.execute("SELECT * FROM utilisateurs WHERE username = %s", ('Tayeb',))
        tayeb = cur.fetchone()

        if not admin or not tayeb:
            cur2 = get_cursor(False)
            if not admin:
                hashed_admin = generate_password_hash('admin')
                cur2.execute("INSERT INTO utilisateurs (username, password, role) VALUES (%s, %s, %s)",
                             ('admin', hashed_admin, 'admin'))
            if not tayeb:
                hashed_tayeb = generate_password_hash('1234')
                cur2.execute("INSERT INTO utilisateurs (username, password, role) VALUES (%s, %s, %s)",
                             ('Tayeb', hashed_tayeb, 'admin'))

            mysql.connection.commit()
            cur2.close()
            print(" Admins par défaut ajoutés avec succès.")

        cur.close()
    except Exception as e:
        print(" Erreur lors de l'ajout de l'admin par défaut :", e)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = get_cursor()
        cur.execute("SELECT * FROM utilisateurs WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = user['username']
            session['role'] = user['role']
            session['user_id'] = user['id']

            # Redirection selon le rôle
            if user['role'] == 'admin':
                return redirect(url_for('accueil'))
            else:
                return redirect(url_for('accueil'))
        else:
            flash('Identifiants incorrects.')
    return render_template('login.html')

@app.route('/user')
@login_required
def user_home():
    if session.get('role') != 'user':
        return redirect(url_for('accueil'))
    return render_template('accueil.html', nom=session['username'])


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Accueil

@app.route('/accueil')
@login_required
def accueil():
    cur = get_cursor()
    stats = {'total_materiels': 0, 'materiels_en_panne': 0, 'total_employes': 0, 'total_services': 0}
    try:
        queries = {
            'total_materiels': "SELECT COUNT(*) AS total FROM materiels",
            'materiels_en_panne': "SELECT COUNT(*) AS total FROM materiels WHERE etat = 'en panne'",
            'total_employes': "SELECT COUNT(*) AS total FROM employes",
            'total_services': "SELECT COUNT(*) AS total FROM services"
        }
        for key, query in queries.items():
            cur.execute(query)
            result = cur.fetchone()
            stats[key] = result['total'] if result else 0
    finally:
        cur.close()
    return render_template('accueil.html', nom=session['username'], stats=stats)


@app.route('/admin/utilisateurs/ajouter', methods=['GET', 'POST'])
@admin_required
def admin_ajouter_utilisateur():
    if request.method == 'POST':
        try:
            username = request.form['username'].strip()
            if not username:
                flash("Le nom d'utilisateur est requis")
                return redirect(url_for('ajouter_utilisateur'))

            password = request.form['password']
            if len(password) < 8:
                flash("Le mot de passe doit contenir au moins 8 caractères")
                return redirect(url_for('ajouter_utilisateur'))

            role = request.form['role']
            valid_roles = ['admin', 'user']
            if role not in valid_roles:
                flash("Rôle invalide")
                return redirect(url_for('ajouter_utilisateur'))

            # Vérifier si l'utilisateur existe déjà
            cur = get_cursor(True)
            cur.execute("SELECT id FROM utilisateurs WHERE username = %s", (username,))
            if cur.fetchone():
                flash("Ce nom d'utilisateur existe déjà")
                return redirect(url_for('ajouter_utilisateur'))

            # Hash du mot de passe
            hashed_pw = generate_password_hash(password)

            # Insertion
            cur.execute(
                "INSERT INTO utilisateurs (username, password, role) VALUES (%s, %s, %s)",
                (username, hashed_pw, role)
            )
            mysql.connection.commit()
            flash("Utilisateur créé avec succès")
            return redirect(url_for('gestion_utilisateurs'))

        except Exception as e:
            mysql.connection.rollback()
            flash(f"Erreur lors de la création : {str(e)}")
            app.logger.error(f"Erreur création utilisateur : {str(e)}")
        finally:
            cur.close()

    # Pour la méthode GET, afficher le formulaire
    return render_template('ajouter_utilisateur.html',
                           nom=session.get('username'),
                           roles=['admin', 'user'])
@app.route('/admin/utilisateurs/supprimer/<int:id>')
@admin_required
def admin_supprimer_utilisateur(id):
    cur = get_cursor(False)
    cur.execute("DELETE FROM utilisateurs WHERE id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    flash("Utilisateur supprimé.")
    return redirect(url_for('gestion_utilisateurs'))

# Gestion des employés

@app.route('/employes')
@login_required
def liste_employes():
    matricule_filter = request.args.get('matricule', '').strip()
    nom_filter = request.args.get('nom', '').strip()
    prenom_filter = request.args.get('prenom', '').strip()
    poste_filter = request.args.get('poste', '').strip()
    email_filter = request.args.get('email', '').strip()
    service_filter = request.args.get('service', '').strip()

    query = """
        SELECT e.*, s.nom AS service_nom
        FROM employes e
        LEFT JOIN services s ON e.service_id = s.id
        WHERE 1=1
    """
    params = []

    if matricule_filter:
        query += " AND e.matricule LIKE %s"
        params.append(f"%{matricule_filter}%")
    if nom_filter:
        query += " AND e.nom LIKE %s"
        params.append(f"%{nom_filter}%")
    if prenom_filter:
        query += " AND e.prenom LIKE %s"
        params.append(f"%{prenom_filter}%")
    if poste_filter:
        query += " AND e.poste LIKE %s"
        params.append(f"%{poste_filter}%")
    if email_filter:
        query += " AND e.email LIKE %s"
        params.append(f"%{email_filter}%")
    if service_filter:
        query += " AND e.service_id = %s"
        params.append(service_filter)

    query += " ORDER BY e.nom"

    cur = get_cursor()
    cur.execute(query, tuple(params))
    employes = cur.fetchall()

    cur.execute("SELECT id, nom FROM services ORDER BY nom")
    services = cur.fetchall()
    cur.close()

    return render_template('employes.html', employes=employes, services=services, nom=session['username'])

@app.route('/employes/ajouter', methods=['GET', 'POST'])
@login_required
def ajouter_employe():
    services = get_services()
    if request.method == 'POST':
        data = {
            'nom': request.form['nom'],
            'prenom': request.form['prenom'],
            'matricule': request.form['matricule'],
            'date_recrutement': request.form['date_recrutement'],
            'poste': request.form['poste'],
            'email': request.form['email'],
            'service_id': request.form.get['service']
        }

        cur = get_cursor(False)
        cur.execute("""
            INSERT INTO employes (nom, prenom, matricule, date_recrutement, poste, email, service_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, tuple(data.values()))
        employe_id = cur.lastrowid
        mysql.connection.commit()
        cur.close()

        enregistrer_historique(session['username'], "ajout", "employe", employe_id,
                               f"Ajout employé {data['nom']} {data['prenom']}")
        return redirect(url_for('liste_employes'))
    return render_template('ajouter_employe.html', services=services, nom=session['username'])


@app.route('/employes/modifier/<int:id>', methods=['GET', 'POST'])
@login_required
def modifier_employe(id):
    # Récupération des services et de l'employé
    services = get_services()
    cur = get_cursor()

    try:
        # Requête améliorée avec jointure pour récupérer aussi les infos du service
        cur.execute("""
            SELECT e.*, s.nom AS service_nom 
            FROM employes e
            LEFT JOIN services s ON e.service_id = s.id
            WHERE e.id = %s
        """, (id,))
        employe = cur.fetchone()

        if not employe:
            flash("Employé non trouvé.", "error")
            return redirect(url_for('liste_employes'))

        if request.method == 'POST':
            # Validation des données
            try:
                data = {
                    'nom': request.form['nom'].strip(),
                    'prenom': request.form['prenom'].strip(),
                    'matricule': request.form['matricule'].strip(),
                    'date_recrutement': request.form['date_recrutement'],
                    'poste': request.form['poste'].strip(),
                    'email': request.form['email'].strip(),
                    'service_id': request.form.get('service', employe['service_id'])
                    # Garde l'ancienne valeur si non fournie
                }

                # Vérification des champs obligatoires
                if not all([data['nom'], data['prenom'], data['matricule']]):
                    flash("Les champs Nom, Prénom et Matricule sont obligatoires.", "error")
                    return redirect(url_for('modifier_employe', id=id))

                # Conversion de la date
                try:
                    datetime.strptime(data['date_recrutement'], '%Y-%m-%d')
                except ValueError:
                    flash("Format de date invalide. Utilisez AAAA-MM-JJ.", "error")
                    return redirect(url_for('modifier_employe', id=id))

                # Mise à jour en base de données
                cur = get_cursor(False)
                cur.execute("""
                    UPDATE employes
                    SET nom=%s, prenom=%s, matricule=%s, date_recrutement=%s,
                        poste=%s, email=%s, service_id=%s
                    WHERE id=%s
                """, (
                    data['nom'], data['prenom'], data['matricule'],
                    data['date_recrutement'], data['poste'],
                    data['email'], data['service_id'], id
                ))
                mysql.connection.commit()

                enregistrer_historique(
                    session['username'],
                    "modification",
                    "employe",
                    id,
                    f"Modification employé {data['nom']} {data['prenom']}"
                )
                flash("Employé modifié avec succès!", "success")
                return redirect(url_for('liste_employes'))

            except Exception as e:
                mysql.connection.rollback()
                flash(f"Erreur lors de la modification: {str(e)}", "error")
                app.logger.error(f"Erreur modification employé: {str(e)}")
                return redirect(url_for('modifier_employe', id=id))

        # Préparation des données pour l'affichage
        employe_data = {
            **employe,
            'service': {
                'id': employe['service_id'],
                'nom': employe.get('service_nom')
            } if employe['service_id'] else None
        }

        return render_template(
            'modifier_employe.html',
            employe=employe_data,
            services=services,
            nom=session['username']
        )

    finally:
        if cur:
            cur.close()


@app.route('/employes/supprimer/<int:id>')
@login_required
def supprimer_employe(id):
    employe = get_employe_info(id)
    if not employe:
        flash("Employé introuvable.")
        return redirect(url_for('liste_employes'))

    cur = get_cursor(False)
    cur.execute("DELETE FROM employes WHERE id=%s", (id,))
    mysql.connection.commit()
    cur.close()

    description = f"Suppression employé {employe['nom']} {employe['prenom']}"
    enregistrer_historique(session['username'], "suppression", "employe", id, description)
    return redirect(url_for('liste_employes'))

# Import/Export Excel Employés

@app.route('/exporter-employes')
@login_required
def exporter_employes():
    cur = get_cursor()
    cur.execute("SELECT * FROM employes")
    rows = cur.fetchall()
    cur.close()

    df = pd.DataFrame(rows)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Employes', index=False)
    output.seek(0)

    return send_file(output, as_attachment=True,
                     download_name='employes.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/importer-employes', methods=['GET', 'POST'])
@login_required
def importer_employes():
    if request.method == 'POST':
        fichier = request.files.get('fichier_excel')
        if not fichier or not allowed_file(fichier.filename):
            flash("Fichier invalide.")
            return redirect(request.url)

        try:
            df = pd.read_excel(fichier)
        except Exception as e:
            flash(f"Erreur lecture fichier Excel : {e}")
            return redirect(request.url)

        cur = get_cursor(False)

        for _, row in df.iterrows():
            # Extraction sécurisée des valeurs, avec gestion de NaN pour service_id
            matricule = row.get('matricule', '')
            nom = row.get('nom', '')
            prenom = row.get('prenom', '')
            poste = row.get('poste', None)
            email = row.get('email', None)
            date_recrutement = row.get('date_recrutement', None)
            service_id = int(row['service_id']) if 'service_id' in row and not pd.isna(row['service_id']) else None

            # Formatage de la date (si besoin)
            if pd.notna(date_recrutement):
                date_recrutement = pd.to_datetime(date_recrutement).strftime('%Y-%m-%d')
            else:
                date_recrutement = None

            # Exécution de la requête d'insertion
            cur.execute("""
                INSERT INTO employes (matricule, nom, prenom, poste, email, date_recrutement, service_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (matricule, nom, prenom, poste, email, date_recrutement, service_id))

        mysql.connection.commit()
        cur.close()
        flash("Employés importés avec succès.")
        return redirect(url_for('liste_employes'))

    return render_template('importer_employes.html', nom=session['username'])
# Gestion des services

@app.route('/services')
@login_required
def liste_services():
    cur = get_cursor()
    cur.execute("SELECT * FROM services")
    services = cur.fetchall()
    cur.close()
    return render_template('services.html', services=services, nom=session['username'])

@app.route('/services/ajouter', methods=['GET', 'POST'])
@login_required
def ajouter_service():
    if request.method == 'POST':
        nom_service = request.form['nom'].strip()
        if not nom_service:
            flash("Le nom du service ne peut pas être vide.")
            return redirect(request.url)

        cur = get_cursor(False)
        cur.execute("INSERT INTO services (nom) VALUES (%s)", (nom_service,))
        service_id = cur.lastrowid
        mysql.connection.commit()
        cur.close()

        enregistrer_historique(session['username'], "ajout", "service", service_id, f"Ajout du service '{nom_service}'")
        return redirect(url_for('liste_services'))
    return render_template('ajouter_service.html', nom=session['username'])

@app.route('/services/modifier/<int:id>', methods=['GET', 'POST'])
@login_required
def modifier_service(id):
    cur = get_cursor()
    cur.execute("SELECT * FROM services WHERE id=%s", (id,))
    service = cur.fetchone()
    cur.close()

    if not service:
        flash("Service non trouvé.")
        return redirect(url_for('liste_services'))

    if request.method == 'POST':
        nouveau_nom = request.form['nom'].strip()
        if not nouveau_nom:
            flash("Le nom du service ne peut pas être vide.")
            return redirect(request.url)

        cur = get_cursor(False)
        cur.execute("UPDATE services SET nom=%s WHERE id=%s", (nouveau_nom, id))
        mysql.connection.commit()
        cur.close()

        description = f"Modification du service ID {id} : '{service['nom']}' → '{nouveau_nom}'"
        enregistrer_historique(session['username'], "modification", "service", id, description)

        flash("Service modifié avec succès.")
        return redirect(url_for('liste_services'))

    return render_template('modifier_service.html', service=service, nom=session['username'])

@app.route('/services/supprimer/<int:id>')
@login_required
def supprimer_service(id):
    cur = get_cursor()
    cur.execute("SELECT * FROM services WHERE id=%s", (id,))
    service = cur.fetchone()
    cur.close()

    if not service:
        flash("Service non trouvé.")
        return redirect(url_for('liste_services'))

    cur = get_cursor(False)
    cur.execute("DELETE FROM services WHERE id=%s", (id,))
    mysql.connection.commit()
    cur.close()

    description = f"Suppression du service ID {id} : '{service['nom']}'"
    enregistrer_historique(session['username'], "suppression", "service", id, description)

    flash("Service supprimé avec succès.")
    return redirect(url_for('liste_services'))

# Import/Export Excel Services

@app.route('/exporter-services')
@login_required
def exporter_services():
    cur = get_cursor()
    cur.execute("SELECT * FROM services")
    rows = cur.fetchall()
    cur.close()

    df = pd.DataFrame(rows)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Services', index=False)
    output.seek(0)

    return send_file(output, as_attachment=True,
                     download_name='services.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/importer-services', methods=['GET', 'POST'])
@login_required
def importer_services():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not allowed_file(file.filename):
            flash("Fichier invalide.")
            return redirect(request.url)

        df = pd.read_excel(file)
        cur = get_cursor(False)
        for _, row in df.iterrows():
            cur.execute("INSERT INTO services (nom) VALUES (%s)", (row['nom'],))
        mysql.connection.commit()
        cur.close()

        flash("Services importés avec succès.")
        return redirect(url_for('liste_services'))
    return render_template('importer_services.html', nom=session['username'])


# Gestion des matériels

@app.route('/materiels')
@login_required
def liste_materiels():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Récupération des paramètres de filtrage
        nom_filter = request.args.get('nom', '').strip()
        type_filter = request.args.get('type', '').strip()
        etat_filter = request.args.get('etat', '').strip()
        employe_filter = request.args.get('employe', '').strip()
        service_filter = request.args.get('service', '').strip()

        # Construction de la requête principale avec correction pour l'affichage du service
        query = """
        SELECT 
            m.id,
            m.reference,
            m.nom,
            m.type,
            m.etat,
            m.service_id,
            m.employe_id,
            CASE
                WHEN m.employe_id IS NOT NULL THEN es.nom
                ELSE s.nom
            END AS service_nom,
            CONCAT(e.prenom, ' ', e.nom) AS employe_nom,
            e.service_id AS employe_service_id
        FROM materiels m
        LEFT JOIN services s ON m.service_id = s.id
        LEFT JOIN employes e ON m.employe_id = e.id
        LEFT JOIN services es ON e.service_id = es.id
        WHERE 1=1
        """
        params = []

        # Ajout des conditions de filtrage
        if nom_filter:
            query += " AND (m.nom LIKE %s OR m.reference LIKE %s)"
            params.extend([f"%{nom_filter}%", f"%{nom_filter}%"])
        if type_filter:
            query += " AND m.type LIKE %s"
            params.append(f"%{type_filter}%")
        if etat_filter:
            query += " AND m.etat = %s"
            params.append(etat_filter)
        if employe_filter:
            query += " AND m.employe_id = %s"
            params.append(employe_filter)
        if service_filter:
            # Filtre sur le service du matériel OU le service de l'employé si affecté
            query += " AND (m.service_id = %s OR (m.employe_id IS NOT NULL AND e.service_id = %s))"
            params.extend([service_filter, service_filter])

        cursor.execute(query, params)
        materiels = cursor.fetchall()

        # Récupération des employés avec leurs services pour les filtres
        cursor.execute("""
            SELECT e.id, CONCAT(e.prenom, ' ', e.nom) AS nom_complet, 
                   e.service_id, s.nom AS service_nom
            FROM employes e
            LEFT JOIN services s ON e.service_id = s.id
            ORDER BY e.nom
        """)
        employes = cursor.fetchall()

        # Récupération de la liste des services pour les filtres
        cursor.execute("SELECT id, nom FROM services ORDER BY nom")
        services = cursor.fetchall()

        # Préparation des données pour le template
        request_args = {
            'nom': nom_filter,
            'type': type_filter,
            'etat': etat_filter,
            'employe': employe_filter,
            'service': service_filter
        }

        return render_template('materiels.html',
                            materiels=materiels,
                            employes=employes,
                            services=services,
                            request_args=request_args)

    except Exception as e:
        print(f"Erreur: {e}")
        flash("Une erreur est survenue lors du chargement des matériels.", "danger")
        return redirect(url_for('home'))

@app.route('/materiels/ajouter', methods=['GET', 'POST'])
@login_required
def ajouter_materiel():
    if request.method == 'POST':
        # Récupère les données du formulaire
        nom = request.form['nom']
        reference = request.form['reference']
        code_immobilisation = request.form['code_immobilisation']
        numero_serie = request.form['numero_serie']
        etat = request.form['etat']
        date_achat = request.form['date_achat']
        remarque = request.form['remarque']
        service_id = request.form['service_id']
        employe_id = request.form['employe_id']

        # Création et insertion
        type_materiel = request.form.get('type')

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO materiels (nom, reference, code_immobilisation, type, numero_serie, etat, date_achat, remarque, service_id, employe_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (nom, reference, code_immobilisation, type_materiel, numero_serie, etat, date_achat, remarque, service_id, employe_id))
        mysql.connection.commit()
        cur.close()

        flash("Matériel ajouté avec succès", "success")
        return redirect(url_for('liste_materiels'))

    # Récupère services et employés pour le formulaire
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nom FROM services")
    services = cur.fetchall()


    cur = mysql.connection.cursor(cursorclass=DictCursor)
    cur.execute("SELECT id, nom, prenom FROM employes")
    employes = cur.fetchall()
    cur.close()

    return render_template("ajouter_materiel.html", services=services, employes=employes)


@app.route('/materiels/detail/<int:materiel_id>')
@login_required
def detail_materiel(materiel_id):
    try:
        # Utilise un DictCursor pour récupérer les résultats sous forme de dictionnaire
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Récupérer les infos du matériel avec les détails du service et de l'employé
        # Version optimisée - une seule requête au lieu de deux
        cur.execute("""
            SELECT m.*, 
                   e.id AS employe_id, e.nom AS employe_nom, e.prenom AS employe_prenom,
                   s.id AS service_id, s.nom AS service_nom
            FROM materiels m
            LEFT JOIN employes e ON m.employe_id = e.id
            LEFT JOIN services s ON e.service_id = s.id OR m.service_id = s.id
            WHERE m.id = %s
        """, (materiel_id,))
        materiel = cur.fetchone()

        if not materiel:
            flash("Matériel introuvable", "danger")
            return redirect(url_for('liste_materiels'))



        return render_template("detail_materiel.html",
                               materiel=materiel)

    except MySQLdb.Error as e:
        flash(f"Erreur de base de données: {str(e)}", "danger")
        app.logger.error(f"Erreur DB dans detail_materiel: {str(e)}")
        return redirect(url_for('detail_materiels'))

    except Exception as e:
        flash("Une erreur inattendue est survenue", "danger")
        app.logger.error(f"Erreur inattendue dans detail_materiel: {str(e)}")
        return redirect(url_for('detail_materiels'))

    finally:
        if 'cur' in locals():
            cur.close()

@app.route('/materiels/modifier/<int:materiel_id>', methods=['GET', 'POST'])
@login_required
def modifier_materiel(materiel_id):
    cur = mysql.connection.cursor(DictCursor)

    try:
        # Récupération complète du matériel avec jointures
        cur.execute("""
            SELECT m.*, 
                   e.id AS employe_id, 
                   e.nom AS employe_nom,
                   e.prenom AS employe_prenom,
                   e.service_id AS employe_service_id,
                   s.nom AS service_nom,
                   s.id AS service_id
            FROM materiels m
            LEFT JOIN employes e ON m.employe_id = e.id
            LEFT JOIN services s ON m.service_id = s.id OR e.service_id = s.id
            WHERE m.id = %s
        """, (materiel_id,))
        materiel = cur.fetchone()

        if not materiel:
            flash("Matériel introuvable", "danger")
            return redirect(url_for('liste_materiels'))

        if request.method == 'POST':
            # Récupération des données du formulaire
            form_data = {
                'nom': request.form['nom'],
                'reference': request.form['reference'],
                'type': request.form['type'],
                'etat': request.form['etat'],
                'employe_id': request.form.get('employe_id') or None,
                'service_id': request.form.get('service_id') or None,
                'numero_serie': request.form.get('numero_serie'),
                'code_immobilisation': request.form.get('code_immobilisation'),
                'date_achat': request.form['date_achat'],
                'remarque': request.form.get('remarque', '')
            }

            # Validation cohérence employé/service
            if form_data['employe_id']:
                cur.execute("SELECT service_id FROM employes WHERE id = %s", (form_data['employe_id'],))
                emp_service = cur.fetchone()
                if emp_service and form_data['service_id'] and emp_service['service_id'] != int(
                        form_data['service_id']):
                    flash("L'employé sélectionné n'appartient pas au service choisi", "warning")
                    form_data['service_id'] = emp_service['service_id']

            # Mise à jour du matériel
            cur.execute("""
                UPDATE materiels
                SET nom = %(nom)s,
                    reference = %(reference)s,
                    numero_serie = %(numero_serie)s,
                    code_immobilisation = %(code_immobilisation)s,
                    type = %(type)s,
                    date_achat = %(date_achat)s,
                    etat = %(etat)s,
                    remarque = %(remarque)s,
                    employe_id = %(employe_id)s,
                    service_id = %(service_id)s
                WHERE id = %(materiel_id)s
            """, {**form_data, 'materiel_id': materiel_id})

            mysql.connection.commit()
            flash("Matériel modifié avec succès", "success")
            return redirect(url_for('liste_materiels'))

        # Récupération des employés avec leur service (champs séparés)
        cur.execute("""
            SELECT e.id, 
                   e.nom,
                   e.prenom,
                   e.service_id,
                   s.nom AS service_nom
            FROM employes e
            LEFT JOIN services s ON e.service_id = s.id
            ORDER BY e.nom, e.prenom
        """)
        employes = cur.fetchall()

        # Récupération des services
        cur.execute("SELECT id, nom FROM services ORDER BY nom")
        services = cur.fetchall()

        return render_template(
            "modifier_materiel.html",
            materiel=materiel,
            employes=employes,
            services=services,
            current_employe_service=materiel.get('employe_service_id')
        )

    except Exception as e:
        mysql.connection.rollback()
        flash(f"Erreur lors de la modification: {str(e)}", "danger")
        return redirect(url_for('liste_materiels'))
    finally:
        cur.close()


@app.route('/materiels/supprimer/<int:materiel_id>')
@login_required
def supprimer_materiel(materiel_id):
    try:
        cur = get_cursor()
        cur.execute("""
            SELECT reference, numero_serie 
            FROM materiels 
            WHERE id = %s
        """, (materiel_id,))
        materiel = cur.fetchone()

        if not materiel:
            flash("Matériel introuvable", "error")
            return redirect(url_for('liste_materiels'))

        # Suppression des entretiens associés d'abord
        cur.execute("DELETE FROM entretiens WHERE materiel_id = %s", (materiel_id,))

        # Puis suppression du matériel
        cur.execute("DELETE FROM materiels WHERE id = %s", (materiel_id,))

        mysql.connection.commit()
        cur.close()

        description = f"Suppression matériel {materiel['reference']} (N° série: {materiel['numero_serie']})"
        enregistrer_historique(
            session['username'],
            "suppression",
            "materiel",
            materiel_id,
            description
        )

        flash("Matériel supprimé avec succès", "success")
        return redirect(url_for('liste_materiels'))

    except Exception as e:
        flash(f"Erreur lors de la suppression du matériel: {str(e)}", "error")
        return redirect(url_for('liste_materiels'))


@app.route('/exporter-materiels')
@login_required
def exporter_materiels():
    try:
        cur = get_cursor()
        cur.execute("""
            SELECT
                m.id,
                m.nom,
                m.reference,
                m.numero_serie,
                m.code_immobilisation,
                m.type,
                m.etat,
                m.remarque,
                m.employe_id,
                m.date_achat,
                s.nom AS service,
                CONCAT(e.prenom, ' ', e.nom) AS employe,
            FROM materiels m
            LEFT JOIN services s ON m.service_id = s.id
            LEFT JOIN employes e ON m.employe_id = e.id
            ORDER BY m.reference
        """)
        rows = cur.fetchall()
        cur.close()

        df = pd.DataFrame(rows)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Materiels', index=False)
        output.seek(0)

        return send_file(
            output,
            as_attachment=True,
            download_name='materiels.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )

    except Exception as e:
        flash(f"Erreur lors de l'export des matériels: {str(e)}", "error")
        return redirect(url_for('liste_materiels'))


@app.route('/importer-materiels', methods=['GET', 'POST'])
@login_required
def importer_materiels():
    if request.method == 'POST':
        try:
            file = request.files.get('file')
            if not file or not allowed_file(file.filename):
                flash("Fichier invalide. Seuls les fichiers Excel sont acceptés", "error")
                return redirect(request.url)

            df = pd.read_excel(file)

            # Vérification des colonnes requises
            required_columns = ['reference', 'numero_serie', 'code_immobilisation', 'type', 'etat', 'date_achat']
            if not all(col in df.columns for col in required_columns):
                flash("Le fichier Excel doit contenir toutes les colonnes requises", "error")
                return redirect(request.url)

            cur = get_cursor(False)
            for _, row in df.iterrows():
                cur.execute("""
                    INSERT INTO materiels 
                    (reference, numero_serie, code_immobilisation, type, etat, date_achat, service_id, employe_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    str(row['reference']),
                    str(row['numero_serie']),
                    str(row['code_immobilisation']),
                    str(row['type']),
                    str(row['etat']),
                    row['date_achat'],
                    int(row['service_id']) if 'service_id' in row and not pd.isna(row['service_id']) else None,
                    int(row['employe_id']) if 'employe_id' in row and not pd.isna(row['employe_id']) else None
                ))

            mysql.connection.commit()
            cur.close()

            flash("Matériels importés avec succès", "success")
            return redirect(url_for('liste_materiels'))

        except Exception as e:
            flash(f"Erreur lors de l'import des matériels: {str(e)}", "error")
            return redirect(request.url)

    return render_template('importer_materiels.html', nom=session['username'])

# Gestion de l'historique

@app.route("/historique")
@login_required
def afficher_historique():
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM historique ORDER BY date_action DESC")
        historique = cur.fetchall()
        cur.close()
        print("DEBUG historique:", historique)  # <-- ajoute ça pour tester
        return render_template("historique.html", historique=historique)
    except Exception as e:
        return render_template("erreur.html", message=str(e))


@app.route('/gestion-utilisateurs')
@login_required
def gestion_utilisateurs():
    if session.get('role') != 'admin':
        flash("Accès interdit")
        return redirect(url_for('accueil'))

    cur = get_cursor()
    cur.execute("""
        SELECT u.*, e.nom AS employe_nom, e.prenom AS employe_prenom
        FROM utilisateurs u
        LEFT JOIN employes e ON u.employe_id = e.id
    """)
    utilisateurs = cur.fetchall()
    cur.execute("SELECT id, nom, prenom FROM employes")
    employes = cur.fetchall()
    cur.close()

    return render_template("gestion_utilisateurs.html", utilisateurs=utilisateurs, employes=employes, nom=session['username'])

@app.route('/utilisateurs/ajouter', methods=['GET', 'POST'])
@login_required
def ajouter_utilisateur():
    employes = get_employes()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        employe_id = request.form.get('employe_id') or None

        hashed = generate_password_hash(password)

        cur = get_cursor(False)
        cur.execute("""
            INSERT INTO utilisateurs (username, password, role, employe_id)
            VALUES (%s, %s, %s, %s)
        """, (username, hashed, role, employe_id))
        mysql.connection.commit()
        cur.close()

        flash("Utilisateur ajouté avec succès.")
        return redirect(url_for('gestion_utilisateurs'))

    return render_template('ajouter_utilisateur.html', employes=employes, nom=session['username'])


@app.route('/utilisateurs/modifier/<int:id>', methods=['GET', 'POST'])
@login_required
def modifier_utilisateur(id):
    cur = get_cursor()
    cur.execute("SELECT * FROM utilisateurs WHERE id = %s", (id,))
    utilisateur = cur.fetchone()
    cur.close()

    if not utilisateur:
        flash("Utilisateur introuvable.")
        return redirect(url_for('gestion_utilisateurs'))

    employes = get_employes()

    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        employe_id = request.form.get('employe_id') or None
        nouveau_mdp = request.form.get('password')

        cur = get_cursor(False)
        if nouveau_mdp:
            hashed = generate_password_hash(nouveau_mdp)
            cur.execute("""
                UPDATE utilisateurs
                SET username=%s, password=%s, role=%s, employe_id=%s
                WHERE id=%s
            """, (username, hashed, role, employe_id, id))
        else:
            cur.execute("""
                UPDATE utilisateurs
                SET username=%s, role=%s, employe_id=%s
                WHERE id=%s
            """, (username, role, employe_id, id))

        mysql.connection.commit()
        cur.close()

        flash("Utilisateur modifié avec succès.")
        return redirect(url_for('gestion_utilisateurs'))

    return render_template('modifier_utilisateur.html', utilisateur=utilisateur, employes=employes, nom=session['username'])


@app.route('/utilisateurs/supprimer/<int:id>')
@login_required
def supprimer_utilisateur(id):
    cur = get_cursor()
    cur.execute("SELECT * FROM utilisateurs WHERE id = %s", (id,))
    utilisateur = cur.fetchone()
    if not utilisateur:
        flash("Utilisateur introuvable.")
        return redirect(url_for('gestion_utilisateurs'))

    cur.execute("DELETE FROM utilisateurs WHERE id = %s", (id,))
    mysql.connection.commit()
    cur.close()

    flash("Utilisateur supprimé avec succès.")
    return redirect(url_for('gestion_utilisateurs'))

@app.route('/statistiques')
@login_required
def statistiques():
    cur = get_cursor()

    # Nombre total d'employés
    cur.execute("SELECT COUNT(*) AS total FROM employes")
    total_employes = cur.fetchone()['total']

    # Nombre total de matériels
    cur.execute("SELECT COUNT(*) AS total FROM materiels")
    total_materiels = cur.fetchone()['total']

    # Nombre de matériels par état
    cur.execute("""
        SELECT etat, COUNT(*) AS count
        FROM materiels
        GROUP BY etat
    """)
    etats = cur.fetchall()

    # Nombre de matériels par service
    cur.execute("""
        SELECT s.nom AS service, COUNT(m.id) AS count
        FROM materiels m
        LEFT JOIN services s ON m.service_id = s.id
        GROUP BY s.nom
    """)
    par_service = cur.fetchall()

    cur.close()

    return render_template("statistiques"".html",
                           total_employes=total_employes,
                           total_materiels=total_materiels,
                           etats=etats,
                           par_service=par_service,
                           nom=session['username'])

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xlsx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ✅ EXPORTATION DES MATERIELS
@app.route('/export_materiels')
def export_materiels():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM materiels")
    materiels = cur.fetchall()
    cur.close()

    df = pd.DataFrame(materiels, columns=['id', 'nom', 'reference', 'type', 'etat', 'date_achat', 'employe_id', 'service_id'])
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Materiels')
    output.seek(0)

    return send_file(output, download_name="materiels.xlsx", as_attachment=True)

# ✅ IMPORTATION DES MATERIELS
@app.route('/import_materiels', methods=['POST'])
def import_materiels():
    if 'file' not in request.files:
        flash("Aucun fichier sélectionné")
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash("Nom de fichier vide")
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        df = pd.read_excel(filepath)

        cur = mysql.connection.cursor()
        for index, row in df.iterrows():
            cur.execute("""
                INSERT INTO materiels (nom, reference, type, etat, date_achat, employe_id, service_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (row['nom'], row['reference'], row['type'], row['etat'], row['date_achat'], row['employe_id'], row['service_id']))
        mysql.connection.commit()
        cur.close()
        os.remove(filepath)
        flash("Importation réussie.")
    else:
        flash("Format non supporté. Utilisez .xlsx")
    return redirect(url_for('dashboard'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template("erreur.html", erreur="Page non trouvée (404)."), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("erreur.html", erreur="Erreur interne du serveur (500)."), 500

@app.errorhandler(Exception)
def handle_exception(e):
    return render_template("erreur.html", erreur=str(e)), 500


# Lancement de l'application

if __name__ == '__main__':
    app.run(debug=True)