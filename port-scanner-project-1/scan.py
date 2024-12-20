def try_ssh_login(target_ip, credentials):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for username, password in credentials:
        try:
            ssh.connect(target_ip, username=username, password=password, timeout=5)
            print(f"Successful SSH login with {username}:{password}")
            ssh.close()
            return True
        except paramiko.AuthenticationException:
            print(f"Failed SSH login attempt with {username}:{password}")
        except paramiko.SSHException as e:
            print(f"Error connecting to SSH: {e}")
    return False


def try_ftp_login(target_ip, credentials):
    try:
        ftp = FTP(target_ip, timeout=5)
        for username, password in credentials:
            try:
                ftp.login(user=username, passwd=password)
                print(f"Successful FTP login with {username}:{password}")
                ftp.quit()
                return True
            except Exception as e:
                print(f"Failed FTP login with {username}:{password}: {e}")
    except Exception as e:
        print(f"Error connecting to FTP: {e}")
    return False

def try_http_login(target_ip, credentials):
    url = f"http://{target_ip}"
    for username, password in credentials:
        try:
            response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=5)
            if response.status_code == 200:
                print(f"Successful login on HTTP with {username}:{password}")
                return True
            else:
                print(f"Failed login attempt on HTTP with {username}:{password}")
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to HTTP: {e}")
    return False