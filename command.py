class Command:

    def ca(self,args):
        print("ca", args)

    def cert(self,args):
        print("cert", args)

    def run(self, args):
        fn = eval(f"self.{args.command}")
        fn(args)
