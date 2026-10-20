
import torch
from torch import nn

# Make our experiment reproducible
torch.manual_seed(42)

# Use NVIDIA GPU when available
device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

print("=== Experiment 02: First Neural Network ===")
print(f"Device: {device}")

# Create example training data
# Our model will learn: y = 2x + 1
x = torch.linspace(-10, 10, 200).reshape(-1, 1).to(device)
y = 2 * x + 1

# Build our neural network
model = nn.Sequential(
    nn.Linear(1, 16),
    nn.ReLU(),
    nn.Linear(16, 1)
).to(device)

# Define how learning happens
loss_function = nn.MSELoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.01)

# Train the model
for epoch in range(1001):
    optimizer.zero_grad()

    predictions = model(x)
    loss = loss_function(predictions, y)

    loss.backward()
    optimizer.step()

    if epoch % 200 == 0:
        print(f"Epoch {epoch}: Loss = {loss.item():.6f}")

# Test with a new value
model.eval()

with torch.no_grad():
    test_input = torch.tensor([[5.0]], device=device)
    prediction = model(test_input)

print("\n=== Results ===")
print("Input: 5")
print(f"Expected output: 11")
print(f"AI prediction: {prediction.item():.4f}")
print(f"Final loss: {loss.item():.6f}")
print(f"Model device: {next(model.parameters()).device}")

print("\nExperiment completed!")
