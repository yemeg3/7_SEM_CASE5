from flask import Flask, render_template, request, redirect, url_for, session, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io
from flask import make_response

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/case5'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    transaction_type = db.Column(db.String(10), nullable=False)

    user = db.relationship('User', backref='transactions')

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('user'))
        else:
            error = 'Неверный логин или пароль'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/user', methods=['GET', 'POST'])
def user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        selected_category = request.args.get('category')
        if selected_category:
            transactions = Transaction.query.filter_by(user_id=user.id, category=selected_category).all()
        else:
            transactions = Transaction.query.filter_by(user_id=user.id).all()
        total_income = sum(t.amount for t in transactions if t.transaction_type == 'income')
        total_expense = sum(t.amount for t in transactions if t.transaction_type == 'expense')
        total_balance = total_income - total_expense

        categories_income = {}
        categories_expense = {}

        for t in transactions:
            if t.transaction_type == 'income':
                categories_income[t.category] = categories_income.get(t.category, 0) + t.amount
            else:
                categories_expense[t.category] = categories_expense.get(t.category, 0) + t.amount

        income_labels = list(categories_income.keys())
        income_data = list(categories_income.values())
        expense_labels = list(categories_expense.keys())
        expense_data = list(categories_expense.values())

        categories = Transaction.query.with_entities(Transaction.category).distinct().all()

        return render_template('user.html', user=user, transactions=transactions,
                               total_balance=total_balance,
                               income_labels=income_labels, income_data=income_data,
                               expense_labels=expense_labels, expense_data=expense_data,
                               categories=categories)
    return redirect(url_for('login'))

@app.route('/import', methods=['POST'])
def import_transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    file = request.files['file']

    if not file:
        return "Нет файла для импорта."

    content = file.stream.read().decode('utf-8')
    reader = csv.reader(content.splitlines())
    next(reader)

    for row in reader:
        try:
            amount = float(row[0])
            category = row[1]
            transaction_type = row[2]
            description = row[3] if row[3] and row[3].strip() else ''

            if transaction_type not in ['income', 'expense']:
                print(f"Неизвестный тип транзакции: {transaction_type}")
                continue

            new_transaction = Transaction(user_id=user.id, amount=amount, category=category,
                                          description=description, transaction_type=transaction_type)
            db.session.add(new_transaction)
        except ValueError as e:
            print(f"Ошибка при обработке строки {row}: {e}")
        except Exception as e:
            print(f"Ошибка: {e}")

    db.session.commit()
    return redirect(url_for('user'))

@app.route('/export')
def export_transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    transactions = Transaction.query.filter_by(user_id=user.id).all()

    if not transactions:
        return "У вас нет транзакций для экспорта."

    print(f"Найдено транзакций: {len(transactions)}")

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(['Сумма', 'Категория', 'Тип транзакции', 'Описание'])

    for transaction in transactions:
        print(f"Транзакция: {transaction.amount}, {transaction.category}, {transaction.transaction_type}, {transaction.description}")
        writer.writerow([transaction.amount, transaction.category, transaction.transaction_type, transaction.description])

    output.seek(0)
    response = Response(output.getvalue(), content_type='text/csv; charset=utf-8')
    response.headers["Content-Disposition"] = "attachment; filename=transactions.csv"

    return response

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    if 'user_id' in session:
        amount = request.form['amount']
        category = request.form['category']
        description = request.form['description']
        transaction_type = request.form['transaction_type']

        new_transaction = Transaction(
            user_id=session['user_id'],
            amount=amount,
            category=category,
            description=description,
            transaction_type=transaction_type
        )

        db.session.add(new_transaction)
        db.session.commit()

        return redirect(url_for('user'))
    return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
