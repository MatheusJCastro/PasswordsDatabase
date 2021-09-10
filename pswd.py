#########################################################
# Passwords Database v1.1                               #
# Written by: Matheus J. Castro                         #
# Under MIT License                                     #
# More information on:                                  #
# https://github.com/MatheusJCastro/PasswordsDatabase   #
#########################################################


from pysqlcipher3 import dbapi2 as sqlcipher
from getpass import getpass
import pandas.io.sql
import pandas as pd
import numpy as np
import time
import sys
import os


version = 1.1


def import_csv(fl_name):
    print("Reading...", end="")
    try:
        # Import csv to a data frame
        data = pd.read_csv(fl_name)
    except FileNotFoundError:
        sys.exit("\nFile \033[1;3;31m{}\033[m not found.".format(fl_name))

    # Lower Case the column names
    columns_names = {}
    for i in data.columns:
        columns_names[i] = i.lower()
    data.rename(columns=columns_names, inplace=True)

    # Test if all recognized columns are available on data frame
    known_names = ["name", "url", "username", "password"]
    for name in known_names:
        if not any(i == name for i in data.columns):
            sys.exit("\nFile \033[1;3;31m{}\033[m doesn't have the \033[1;3;31m{}\033[m column.".format(fl_name, name))

    data = data[known_names]
    print("ok")

    return data


def export_csv(data, fl_name):
    print("Writing...", end="")
    data.to_csv(fl_name, index=False)
    print("ok")


def remove_empty_pswd(data, noask=False):
    if not noask:
        no_pswd = np.where(pd.isnull(data["password"]))[0]
        answer = input("{} empty passwords entries were found:".format(len(no_pswd)) + "\n"
                       "Rows = {}".format(no_pswd + 1) + "\n"
                       "Do you wanna to remove it?" + "\n"
                       "[Y/n]: ")
        if answer == "n":
            print("Not removing it.")
            return data

    print("Removing empty passwords...", end="")
    data.dropna(subset=["password"], inplace=True)
    print("ok")

    return data


def remove_duplicated(data, noask=False):
    if not noask:
        dup = np.where(data[["name", "username", "password"]].duplicated() == True)[0]
        answer = input("{} duplicated entries were found:".format(len(dup)) + "\n"
                       "Rows = {}".format(dup + 1) + "\n"
                       "Do you wanna to remove it?" + "\n"
                       "[Y/n]: ")
        if answer == "n":
            print("Not removing it.")
            return data

    print("Removing duplicated entries...", end="")
    data.drop_duplicates(subset=["name", "username", "password"], keep="first", inplace=True)
    print("ok")

    return data


def sort_dataFrame(data, noask=False):
    if not noask:
        answer = input("Do you want to resort DataFrame:" + "\n"
                                                            "[Y/n]: ")
        if answer == "n":
            print("Not resorting it.")
            return data

    print("Sorting...", end="")
    data.sort_values("name", axis=0, inplace=True)
    data.reset_index(drop=True, inplace=True)
    print("ok")

    return data


def add_new_entry(data, noask=False):
    new_data = {}

    print("Adding new entry:")
    new_data["name"] = input("Enter the name: ")
    new_data["url"] = input("Enter the url: ")
    new_data["username"] = input("Enter the username: ")
    new_data["password"] = input("Enter the password: ")

    print("Adding...", end="")
    data = data.append(new_data, ignore_index=True)
    data = sort_dataFrame(data, noask=noask)
    print("ok")

    return data


def open_database(fl_name, pswd=None):
    pswd_verify = ""
    if not os.path.isfile(fl_name):
        conn = sqlcipher.connect(fl_name)
        if pswd != "None":
            if pswd is None:
                while pswd != pswd_verify:
                    pswd = getpass("Type the new database password (empty for no password): ")
                    pswd_verify = getpass("Type the new password again: ")
                    print("Passwords doesn't match.") if pswd != pswd_verify else None
            conn.execute("PRAGMA KEY='{}'".format(pswd))
    else:
        count = 0
        while True:
            conn = sqlcipher.connect(fl_name)
            if pswd != "None":
                if pswd is None:
                    pswd = getpass("Type the database password: ")
                conn.execute("PRAGMA KEY='{}'".format(pswd))

            try:
                pd.read_sql_query("SELECT * from passwords", conn)
            except pandas.io.sql.DatabaseError:
                print("\033[31mWrong Password. Try again.\033[m")
                count += 1
                pswd = None
            else:
                break

            if count >= 3:
                sys.exit("\033[31mThree failed attempts. Exiting.\033[m")
    # dataBase.execute("CREATE TABLE IF NOT EXISTS passwords \
    #                  ([name] TEXT, \
    #                   [url] TEXT, \
    #                   [username] TEXT, \
    #                   [password] TEXT)")

    return conn


def read_database(conn):
    print("Reading...", end="")
    data = pd.read_sql_query("SELECT * from passwords", conn)
    print("ok")

    return data


def remove_encryption(db, fl_name):
    print("Removing...", end="")
    db.execute("ATTACH DATABASE 'decrypted_{}' AS encrypted KEY ''".format(fl_name))
    db.execute("SELECT sqlcipher_export('encrypted')")
    db.execute("DETACH DATABASE encrypted")
    print("ok")


def add_encryption(db, fl_name):
    pswd = ""
    pswd_verify = None

    while pswd != pswd_verify:
        pswd = getpass("Type the new password: ")
        pswd_verify = getpass("Type the new password again: ")
        print("\033[31mPasswords doesn't match.\033[m") if pswd != pswd_verify else None
        if pswd == "":
            print("\033[31mPassword cannot be empty.\033[m")
            pswd_verify = None

    print("Adding encryption...", end="")
    db.execute("ATTACH DATABASE 'encrypted_{}' AS encrypted KEY '{}'".format(fl_name, pswd))
    db.execute("SELECT sqlcipher_export('encrypted')")
    db.execute("DETACH DATABASE encrypted")
    print("ok")


def write_database(data, conn):
    print("Writing...", end="")
    data.to_sql("passwords", conn, if_exists="replace", index=False)
    print("ok")


def arg_resolution(args):
    op = {"csv_name": None,
          "db_name": None,
          "pswd": None,
          "noask": False,
          "csvdatabase": False,
          "databasecsv": False,
          "encrypt": False,
          "decrypt": False}

    if any(i == "-h" or i == "--help" for i in args):
        help_show()
    if any(i == "-v" or i == "--version" for i in args):
        sys.exit("Passwords Database v{}".format(version))
    if any(i == "--csv" for i in args):
        ind = np.where(args == "--csv")[0][0]
        op["csv_name"] = args[ind + 1]
    if any(i == "--db" for i in args):
        ind = np.where(args == "--db")[0][0]
        op["db_name"] = args[ind + 1]
    if any(i == "--no-ask" for i in args):
        op["noask"] = True
    if any(i == "--csv-to-database" for i in args):
        op["csvdatabase"] = True
    elif any(i == "--database-to-csv" for i in args):
        op["databasecsv"] = True
    if any(i == "--encrypt" for i in args):
        op["encrypt"] = True
    elif any(i == "--decrypt" for i in args):
        op["decrypt"] = True
    if any(i == "-p" for i in args):
        ind = np.where(args == "-p")[0][0]
        op["pswd"] = args[ind + 1]

    return op


def help_show():
    sys.exit("\t\033[1;3;31mHelp Section\033[m\n"
             "\tPasswords Database v{}\n".format(version) +
             "\tWritten by: Matheus J. Castro\n"
             "\tUnder MIT License\n"
             "\tMore information on: https://github.com/MatheusJCastro/PasswordsDatabase\n\n"
             "Usage: python3 pswd.py [options]\n"
             "\033[1;30;47mNo options will open the interactive menu\033[m\n\n"
             "Options are:\n"
             "-h, --help\t |\tShow this help\n"
             "\033[30;47m-v, --version\033[m\t |\t\033[30;47mShow the version\033[m\n"
             "--csv [argument] |\tDefine CSV file name\n"
             "\033[30;47m--db  [argument]\033[m |\t\033[30;47mDefine SQLite3 Database name\033[m\n"
             "--no-ask\t |\tNo ask wil be prompted\n"
             "\033[30;47m--csv-to-database\033[m|\t\033[30;47mDefault read CSV and write SQLite3 Database\033[m\n"
             "\t\t |\t\033[30;47mThis includes the remove blank passwords,\033[m\n"
             "\t\t |\t\033[30;47mremove duplicated entries, sort Database by name,\033[m\n"
             "\t\t |\t\033[30;47mand write it into a SQLite3 Database\033[m\n"
             "--database-to-csv|\tSame as \033[3m--csv-to-database\033[m but reads SQLite3\n"
             "\t\t |\tDatabase and write a CSV file\n"
             "\033[30;47m--encrypt\033[m\t |\t\033[30;47mEncrypt SQLite3 Database\033[m\n"
             "--decrypt\t |\tDecrypt SQLite3 Database\n"
             "\033[30;47m-p [argument]\033[m\t |\t\033[30;47mSet encryption password. "
             "\033[1;3mNone\033[0;30;47m for no password.\033[m")


def interactive_menu():
    def clear_print():
        menu = "\tPasswords Database v{}\n".format(version) + \
               "\tWritten by: Matheus J. Castro\n" \
               "\tUnder MIT License\n" \
               "\tMore information on: https://github.com/MatheusJCastro/PasswordsDatabase\n\n" \
               "What to do?\n" \
               " 1- Read CSV password file\n" \
               " 2- Export Database to a CSV file\n" \
               " 3- Remove empty passwords os DataFrame\n" \
               " 4- Remove duplicated entries on DataFrame\n" \
               " 5- Resort DataFrame by name\n" \
               " 6- Add new entry to DataFrame\n" \
               " 7- Open/Create SQLite3 Database\n" \
               " 8- Write to a Database\n" \
               " 9- Read from a Database\n" \
               "10- Encrypt Database\n" \
               "11- Decrypt Database\n" \
               "12- View loaded DataFrame\n" \
               "13- Default Read CSV then write to a Database\n" \
               "14- Default Read Database then write to a CSV\n" \
               "15- Exit\n"

        os.system('cls' if os.name == 'nt' else 'clear')
        print(menu)

    clear_print()

    data = dataBase = db_name = op = None
    while op != 15:
        try:
            op = int(input("Type the number option: "))
        except ValueError:
            op = None

        if op == 1:
            clear_print()
            csv_name = input("CSV file name: ")
            data = import_csv(csv_name)
        elif op == 2:
            clear_print()
            csv_name = input("CSV file name: ")
            export_csv(data, csv_name)
        elif op == 3:
            clear_print()
            data = remove_empty_pswd(data, noask=True)
        elif op == 4:
            clear_print()
            data = remove_duplicated(data, noask=True)
        elif op == 5:
            clear_print()
            data = sort_dataFrame(data, noask=True)
        elif op == 6:
            clear_print()
            data = add_new_entry(data, noask=False)
        elif op == 7:
            clear_print()
            db_name = input("SQLite3 Database name: ")
            dataBase = open_database(db_name)
        elif op == 8:
            clear_print()
            write_database(data, dataBase)
        elif op == 9:
            clear_print()
            data = read_database(dataBase)
        elif op == 10:
            clear_print()
            add_encryption(dataBase, db_name)
        elif op == 11:
            clear_print()
            remove_encryption(dataBase, db_name)
        elif op == 12:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(data)
            time.sleep(5)
            clear_print()
        elif op == 13:
            clear_print()

            csv_name = input("CSV file name: ")
            data = import_csv(csv_name)
            db_name = input("SQLite3 Database name: ")
            dataBase = open_database(db_name)

            data = remove_empty_pswd(data, noask=True)
            data = remove_duplicated(data, noask=True)
            data = sort_dataFrame(data, noask=True)
            write_database(data, dataBase)
        elif op == 14:
            clear_print()

            db_name = input("SQLite3 Database name: ")
            if not os.path.isfile(db_name):
                sys.exit("File \033[1;3;31m{}\033[m not found.".format(db_name))
            else:
                dataBase = open_database(db_name)

                data = read_database(dataBase)
                data = remove_empty_pswd(data, noask=True)
                data = remove_duplicated(data, noask=True)
                data = sort_dataFrame(data, noask=True)

                csv_name = input("CSV file name: ")
                export_csv(data, csv_name)
        else:
            clear_print()
            print("\033[31mInvalid option.\033[m")

    os.system('cls' if os.name == 'nt' else 'clear')


def main(args):
    if len(args) == 0:
        interactive_menu()
    else:
        op = arg_resolution(args)

        if op["db_name"] is None:
            op["db_name"] = input("SQLite3 Database name: ")
        dataBase = open_database(op["db_name"], pswd=op["pswd"])

        if op["csvdatabase"]:
            if op["csv_name"] is None:
                op["csv_name"] = input("CSV file name: ")
            data = import_csv(op["csv_name"])

            data = remove_empty_pswd(data, noask=op["noask"])
            data = remove_duplicated(data, noask=op["noask"])
            data = sort_dataFrame(data, noask=op["noask"])
            write_database(data, dataBase)

        elif op["databasecsv"]:

            data = read_database(dataBase)
            data = remove_empty_pswd(data, noask=op["noask"])
            data = remove_duplicated(data, noask=op["noask"])
            data = sort_dataFrame(data, noask=op["noask"])

            if op["csv_name"] is None:
                op["csv_name"] = input("CSV file name: ")
            export_csv(data, op["csv_name"])

        elif op["encrypt"]:
            add_encryption(dataBase, op["db_name"])

        elif op["decrypt"]:
            remove_encryption(dataBase, op["db_name"])


if __name__ == '__main__':
    arg = np.asarray(sys.argv[1:])
    main(arg)
