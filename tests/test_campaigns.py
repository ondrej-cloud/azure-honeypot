import re
import unittest

from pipeline.campaigns import classify, normalize

ID = re.compile(r"^[a-z0-9-]{1,40}$")

# Command sequences seen on the live sensor (Cowrie 3.1.2 on Azure, 2026-10-14).
UNAME = ["uname -s -v -n -r -m"]
ENV_SCRIPT = ["export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH\n"
              "uname=$(uname -s -v -n -m 2>/dev/null || /bin/uname -s -v -n -m 2>/dev/null)"]
HISILICON = ["sh", "shell", "enable", "system", "ping; sh", "", "/bin/busybox HISILICON",
             "/bin/busybox cat /proc/self/exe || cat /proc/self/exe"]
HISILICON_DROP = HISILICON[:7] + [">/var/.f && chmod 777 /var/.f && /var/.f && cd /var/;"]
UNSTABLE = ["enable", "linuxshell", "system", "shell", "sh", "/bin/busybox UNSTABLE"]
WICKED = ["enable", "system", "shell", "sh", "SH", "/bin/busybox WICKED"]
BUSYBOX_CHECK = ["enable", "linuxshell", "system", "shell", "sh"]


class CampaignTest(unittest.TestCase):
    def test_mirai_tags(self):
        self.assertEqual(classify(HISILICON), ("mirai-hisilicon", "Mirai-style loader (HISILICON)", True))
        self.assertEqual(classify(HISILICON_DROP)[0], "mirai-hisilicon")   # both stages, one campaign
        self.assertEqual(classify(UNSTABLE)[0], "mirai-unstable")
        self.assertEqual(classify(WICKED)[0], "mirai-wicked")
        self.assertEqual(classify(["echo SHELL_TEST", "/bin/busybox TEST_1; cat /proc"])[0], "mirai-test-1")

    def test_lowercase_applets_are_not_tags(self):
        cid, _name, known = classify(["/bin/busybox cat /proc/self/exe", "busybox wget http://x"])
        self.assertTrue(cid.startswith("c-"))
        self.assertFalse(known)

    def test_named_families(self):
        outlaw = ['cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA mdrfckr">>.ssh/authorized_keys']
        self.assertEqual(classify(outlaw)[:2], ("outlaw-mdrfckr", "Outlaw botnet (mdrfckr SSH key)"))
        self.assertEqual(classify(["./.redtail ssh"])[0], "redtail")
        self.assertEqual(classify(["/tmp/x -o stratum+tcp://pool:3333"])[0], "xmrig-miner")
        self.assertEqual(classify(["chmod +x xmrig"])[0], "xmrig-miner")

    def test_clusters(self):
        cid, name, known = classify(UNAME)
        self.assertRegex(cid, r"^c-[0-9a-f]{8}$")
        self.assertEqual((name, known), ("Cluster: uname -s -v -n -r -m", False))
        self.assertTrue(classify(ENV_SCRIPT)[1].startswith("Cluster: export PATH=/usr/local/sbin"))
        self.assertLessEqual(len(classify(ENV_SCRIPT)[1]), len("Cluster: ") + 48)
        self.assertEqual(classify(BUSYBOX_CHECK)[1], "Cluster: enable; linuxshell; system; shell; sh")
        self.assertEqual(classify(["echo INFECT_CHECK"])[1], "Cluster: echo INFECT_CHECK")
        self.assertEqual(classify(["ps | grep '[Mm]iner'"])[1], "Cluster: ps | grep '[Mm]iner'")
        self.assertEqual(classify([])[1], "Cluster: (empty)")

    def test_fingerprint_ignores_noise(self):
        a = classify(["echo 'root:Xk29'|chpasswd", "uname  -a", "uname -a"])
        b = classify(["echo 'root:Qp71'|chpasswd", "uname -a"])
        self.assertNotEqual(a[0], b[0])                       # different letters, different script
        self.assertEqual(classify(["sleep 5", "id"])[0], classify(["sleep 30", "id", "id"])[0])
        self.assertEqual(normalize([" a  b ", "a b", "x12y3"]), ["a b", "x0y0"])
        self.assertEqual(classify(["sleep 5"])[1], "Cluster: sleep 5")   # name keeps the real text

    def test_hostile_names_are_bounded_and_printable(self):
        for commands in (["<script>alert(1)</script>" * 50], ["\x1b[31mred\x07\x00"], ["‮evil"],
                         ["/bin/busybox " + "A" * 300]):
            cid, name, _known = classify(commands)
            self.assertRegex(cid, ID)
            self.assertTrue(name.isprintable())
            self.assertLessEqual(len(name), 60)


if __name__ == "__main__":
    unittest.main()
