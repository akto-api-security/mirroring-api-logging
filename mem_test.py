import subprocess
import time

def spawn_containers(command):
    try:
        subprocess.run(command, shell=True, check=True)
        print("Docker Compose command executed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing Docker Compose command: {e}")

def destroy_containers(command):
    try:
        subprocess.run(command, shell=True, check=True)
        print("Docker Compose command executed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing Docker Compose command: {e}")

def fetch_logs(container_name, num_logs):
    logs = subprocess.check_output(["docker", "logs", container_name, "--tail", str(num_logs)], stderr=subprocess.STDOUT).decode("utf-8")
    return logs

try:
    spawn_command = "docker-compose -f docker-compose-test.yml up -d"

    spawn_containers(spawn_command)
    print("spawned")

    delay_seconds = 80
    time.sleep(delay_seconds)

    errCnt = 0

    cnt = 0
    while cnt < 100:
        print("cnt")
        print(cnt)
        logs = fetch_logs("mirroring-api-logging-traffic-collector-1", 20)
        print(logs)
        found = "wipeout done" in logs
        if found is False:
            print("error")
            errCnt = errCnt + 1
        time.sleep(4)
        if errCnt > 2:
            raise Exception("log string not found")
        cnt = cnt + 1

except Exception as e:
    print("error ", e)
finally:
    destroy_command = "docker-compose -f docker-compose-test.yml down"
    destroy_containers(destroy_command)