from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair

count = 10
group = PairingGroup("MNT224")
g = group.random(GT)
assert g.initPP(), "failed to init pre-computation table"
h = group.random(GT)
a, b = group.random(ZR, 2)

assert group.InitBenchmark(), "failed to initialize benchmark"
group.StartBenchmark(["RealTime"])
for i in range(count):
    A = g ** a
group.EndBenchmark()
print("With PP: ", group.GetBenchmark("RealTime"))

assert group.InitBenchmark(), "failed to initialize benchmark"
group.StartBenchmark(["RealTime"])
for i in range(count):
    B = h ** b
group.EndBenchmark()
print("Without: ", group.GetBenchmark("RealTime"))