import PortScanner as ps


def main():
    # Initialize a Scanner object that will scan top 50 commonly used ports.
    scanner = ps.PortScanner(target_ports=50)

    host_name = 'baidu.com'

    message = 'put whatever message you want here'

    # This line sets the thread limit of the scanner to 1500
    scanner.set_thread_limit(100)

    # This line sets the timeout delay to 15s
    scanner.set_delay(0.06)

    # This line shows the target port list of the scanner
    scanner.show_target_ports()

    # This line shows the timeout delay of the scanner
    scanner.show_delay()

    # This line shows the top 100 commonly used ports.
    scanner.show_top_k_ports(100)


    scanner.scan(host_name, message)



if __name__ == "__main__":
    main()
