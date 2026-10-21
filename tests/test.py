import re
import time

print('=================================')
print('Entering CALMEY Terminal in...')
print('...Active Terminal')
print('=================================')

name = 'calmey'
password = '1234'

log_in = input("Enter name to proceed: ")
passcode = input('Enter password: ')

if log_in == name and passcode == password:
    print('Verifying credentials...')
    time.sleep(2)
    print(f'\nLogin successful {name}!')
else:
    print('[!] Oops, Login details did not match.')
    input('Press enter to exit')
    exit()

print('\nLoading password files...')
print('Starting password scan...\n')


def check_password(password):
    length_regex = re.compile(r'.{8,}')
    special_regex = re.compile(r'[!@#$%^&*(),.?":{}|<>]')
    digit_regex = re.compile(r'\d')
    uppercase_regex = re.compile(r'[A-Z]')
    lowercase_regex = re.compile(r'[a-z]')

    return (
        length_regex.search(password)
        and special_regex.search(password)
        and digit_regex.search(password)
        and uppercase_regex.search(password)
        and lowercase_regex.search(password)
    )


with open(r'C:\Users\lenov\Desktop\passwords.txt') as file:
    for i, pwd in enumerate(file, start=1):
        pwd = pwd.strip()

        print(f"[{i}] Scanning: {pwd}")
        time.sleep(1)

        if check_password(pwd):
            print(f'✔ Valid Password: {pwd}\n')
        else:
            print(f'✖ Invalid Password: {pwd}\n')

        time.sleep(1)

input('[!] Press Enter to exit program')