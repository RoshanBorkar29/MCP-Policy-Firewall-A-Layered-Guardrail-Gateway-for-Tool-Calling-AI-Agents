"""Generates the synthetic SQLite database containing mock customer data, financial records, and canary PII.
Inputs: Faker seed, schema definitions. Outputs: data/synthetic.db containing populated test tables.
Build plan: Day 1.
"""

from __future__ import annotations

import os
from pathlib import Path
import random
import sqlite3
from faker import Faker

CANARY_SSN_PREFIX = "900-00-"
DEFAULT_DB_PATH = Path(__file__).resolve().parent / "synthetic.db"


def build_database(
    db_path: Path | str = DEFAULT_DB_PATH,
    num_customers: int = 100,
    seed: int = 42,
) -> Path:
    """Creates and populates the synthetic SQLite database with reproducible test data and canary SSNs.

    Args:
        db_path: Filesystem path where the SQLite database should be created.
        num_customers: Number of customer records to generate.
        seed: Random seed for deterministic generation.

    Returns:
        Path to the populated SQLite database file.
    """
    target_path = Path(db_path).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    if target_path.exists():
        target_path.unlink()

    fake = Faker()
    Faker.seed(seed)
    random.seed(seed)

    conn = sqlite3.connect(target_path)
    cursor = conn.cursor()

    cursor.execute("PRAGMA foreign_keys = ON;")

    # Schema definition
    cursor.executescript(
        """
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            ssn TEXT NOT NULL UNIQUE,
            address TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            account_number TEXT NOT NULL UNIQUE,
            account_type TEXT NOT NULL CHECK(account_type IN ('checking', 'savings', 'credit')),
            balance REAL NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('active', 'frozen', 'closed')),
            created_at TEXT NOT NULL,
            FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
        );

        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            transaction_type TEXT NOT NULL CHECK(transaction_type IN ('deposit', 'withdrawal', 'transfer', 'payment')),
            description TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
        );

        CREATE INDEX idx_customers_email ON customers(email);
        CREATE INDEX idx_customers_ssn ON customers(ssn);
        CREATE INDEX idx_accounts_customer ON accounts(customer_id);
        CREATE INDEX idx_transactions_account ON transactions(account_id);
        """
    )

    customers_data = []
    customer_created_dates = []

    for i in range(1, num_customers + 1):
        canary_ssn = f"{CANARY_SSN_PREFIX}{i:04d}"
        created_dt = fake.date_time_between(start_date="-3y", end_date="-30d")
        customer_created_dates.append(created_dt)
        customers_data.append(
            (
                fake.name(),
                fake.unique.email(),
                fake.phone_number(),
                canary_ssn,
                fake.address().replace("\n", ", "),
                created_dt.isoformat(),
            )
        )

    cursor.executemany(
        """
        INSERT INTO customers (name, email, phone, ssn, address, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        customers_data,
    )

    accounts_data = []
    account_id_counter = 1
    transactions_data = []

    account_types = ["checking", "savings", "credit"]
    statuses = ["active", "active", "active", "frozen", "closed"]

    for cust_id_idx, cust_created_dt in enumerate(customer_created_dates, start=1):
        num_accounts = random.randint(1, 3)
        for _ in range(num_accounts):
            acc_type = random.choice(account_types)
            acc_status = random.choice(statuses)
            balance = round(random.uniform(50.0, 25000.0), 2)
            acc_number = f"ACT-{fake.unique.random_number(digits=8, fix_len=True)}"
            acc_created_dt = fake.date_time_between(start_date=cust_created_dt, end_date="now")

            accounts_data.append(
                (
                    account_id_counter,
                    cust_id_idx,
                    acc_number,
                    acc_type,
                    balance,
                    acc_status,
                    acc_created_dt.isoformat(),
                )
            )

            # Generate 3 to 8 transactions per account
            num_tx = random.randint(3, 8)
            tx_types = ["deposit", "withdrawal", "transfer", "payment"]
            for _ in range(num_tx):
                tx_type = random.choice(tx_types)
                tx_amount = round(random.uniform(5.0, 1500.0), 2)
                if tx_type in ("withdrawal", "payment"):
                    tx_amount = -tx_amount
                tx_time_dt = fake.date_time_between(start_date=acc_created_dt, end_date="now")
                tx_desc = f"{tx_type.capitalize()} - {fake.bs()}"
                transactions_data.append(
                    (
                        account_id_counter,
                        tx_amount,
                        tx_type,
                        tx_desc,
                        tx_time_dt.isoformat(),
                    )
                )

            account_id_counter += 1

    cursor.executemany(
        """
        INSERT INTO accounts (id, customer_id, account_number, account_type, balance, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        accounts_data,
    )

    cursor.executemany(
        """
        INSERT INTO transactions (account_id, amount, transaction_type, description, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        transactions_data,
    )

    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM customers")
    total_customers = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM accounts")
    total_accounts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM transactions")
    total_transactions = cursor.fetchone()[0]

    conn.close()

    print(
        f"Database created at: {target_path}\n"
        f"  - Customers:    {total_customers} (all with canary SSN prefix '{CANARY_SSN_PREFIX}')\n"
        f"  - Accounts:     {total_accounts}\n"
        f"  - Transactions: {total_transactions}"
    )

    return target_path


if __name__ == "__main__":
    build_database()
