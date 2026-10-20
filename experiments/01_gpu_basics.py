
import time
import torch

print("=== Enterprise AI Security Lab ===")
print("Experiment 01: CPU vs GPU Computing")

# Check GPU availability
if not torch.cuda.is_available():
    raise RuntimeError("CUDA GPU is not available")

print(f"GPU: {torch.cuda.get_device_name(0)}")
print(f"PyTorch: {torch.__version__}")

# Create two random matrices
size = 1000
a_cpu = torch.rand(size, size)
b_cpu = torch.rand(size, size)

# CPU calculation
start = time.perf_counter()
result_cpu = a_cpu @ b_cpu
cpu_time = time.perf_counter() - start

# Transfer data to GPU
a_gpu = a_cpu.to("cuda")
b_gpu = b_cpu.to("cuda")

# Warm up CUDA before timing
_ = a_gpu @ b_gpu
torch.cuda.synchronize()

# GPU calculation
start = time.perf_counter()
result_gpu = a_gpu @ b_gpu
torch.cuda.synchronize()
gpu_time = time.perf_counter() - start

# Verify that both results are approximately equal
match = torch.allclose(
    result_cpu, result_gpu.cpu(), rtol=1e-3, atol=1e-3
)

print("\n=== Results ===")
print(f"Matrix size: {size} x {size}")
print(f"CPU time: {cpu_time:.6f} seconds")
print(f"GPU time: {gpu_time:.6f} seconds")
print(f"GPU speedup: {cpu_time / gpu_time:.2f}x")
print(f"Results approximately match: {match}")

print("\nExperiment completed successfully!")
