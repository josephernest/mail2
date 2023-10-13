from mail2 import Client

c = Client("127.0.0.1")
c.login("admin@example.com", "wrong")
c.login("admin@example.com", "abcd")
c.read_mails()
c.add_user("test@example.com", "n26nvml2Kpxk4n")
c.send_mail("admin@example2.com", "First mail2 to the world!")  # requires another instance running
