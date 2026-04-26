# blockchain/threatnet.py
# MISTCODER Threat-Native Blockchain
# ThreatNet — Neural Threat Intelligence Model
#
# ═══════════════════════════════════════════════════════════════
# WHAT THIS IS
# ═══════════════════════════════════════════════════════════════
#
# A neural network built from first principles using only numpy.
# No frameworks. No black boxes. Every weight, every gradient,
# every backpropagation step written by hand.
#
# This is not pattern matching.
# This is not a lookup table.
# This is a model that LEARNS from the certified chain.
#
# Architecture:
#   Input(90) → Dense(128) → ReLU → Dropout(0.3)
#             → Dense(64)  → ReLU → Dropout(0.2)
#             → Dense(32)  → ReLU
#             → Dense(3)   → Softmax
#
# Output classes:
#   0 = CONFIRMED  (certified kill chain)
#   1 = NOVEL      (unseen pattern)
#   2 = DISPUTED   (conflicting signals)
#
# Training data:
#   Every certified block on the MISTCODER chain.
#   Labels come from COVENANT's constitutional verdicts.
#   The chain teaches the model. The model teaches ORACLE.
#
# ═══════════════════════════════════════════════════════════════
# THE MATH — explained line by line
# ═══════════════════════════════════════════════════════════════
#
# Forward pass:
#   Z = W · X + b          (linear transformation)
#   A = ReLU(Z)            (activation — kills negative signals)
#   A = Softmax(Z)         (output — probabilities that sum to 1)
#
# Loss:
#   L = -sum(Y * log(A))   (categorical cross-entropy)
#   Measures how wrong the model is. We minimise this.
#
# Backward pass (backpropagation):
#   dL/dW = X^T · dZ       (gradient of loss w.r.t. weights)
#   dL/db = sum(dZ)        (gradient of loss w.r.t. bias)
#   W = W - lr * dL/dW     (weight update — Adam optimiser)
#
# Adam optimiser:
#   Keeps a running average of gradients (momentum)
#   and a running average of squared gradients (variance).
#   Adapts learning rate per weight.
#   Converges faster and more stably than plain gradient descent.
#
# ═══════════════════════════════════════════════════════════════

from __future__ import annotations

import json
import pickle
import time
import numpy as np
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# ── Paths ─────────────────────────────────────────────────────────────────────
SANDBOX      = Path(__file__).resolve().parent.parent / "sandbox"
WEIGHTS_PATH = SANDBOX / "threatnet_weights.pkl"
VOCAB_PATH   = SANDBOX / "threatnet_vocab.json"
HISTORY_PATH = SANDBOX / "threatnet_history.json"

# ── Architecture ──────────────────────────────────────────────────────────────
INPUT_DIM    = 90     # feature vector size
HIDDEN_1     = 128    # first hidden layer
HIDDEN_2     = 64     # second hidden layer
HIDDEN_3     = 32     # third hidden layer
OUTPUT_DIM   = 3      # CONFIRMED / NOVEL / DISPUTED

# ── Training hyperparameters ──────────────────────────────────────────────────
LEARNING_RATE   = 0.001
EPOCHS          = 200
BATCH_SIZE      = 8
DROPOUT_1       = 0.3
DROPOUT_2       = 0.2
ADAM_BETA1      = 0.9      # momentum decay
ADAM_BETA2      = 0.999    # variance decay
ADAM_EPSILON    = 1e-8     # numerical stability

# ── Label encoding ────────────────────────────────────────────────────────────
LABEL_MAP     = {"CONFIRMED": 0, "NOVEL": 1, "DISPUTED": 2}
LABEL_REVERSE = {0: "CONFIRMED", 1: "NOVEL", 2: "DISPUTED"}

# ── Known CWEs for one-hot encoding ──────────────────────────────────────────
CWE_VOCAB = [
    "CWE-89",  "CWE-79",  "CWE-78",  "CWE-22",  "CWE-94",
    "CWE-312", "CWE-502", "CWE-20",  "CWE-611", "CWE-327",
    "CWE-798", "CWE-200", "CWE-400", "CWE-306", "CWE-352",
    "CWE-732", "CWE-119", "CWE-125", "CWE-787", "CWE-416",
    "CWE-476", "CWE-190", "CWE-369", "CWE-362", "CWE-377",
    "CWE-426", "CWE-427", "CWE-428", "CWE-434", "CWE-601",
]  # 30 CWEs

CALL_VOCAB = [
    "eval_exec",  "sql_query",    "file_path",      "password",
    "weak_hash",  "deserialization", "path_traversal", "hardcoded_secret",
    "high_entropy_string", "sql_inject", "eval",    "exec",
    "open",       "read",         "write",          "request",
    "input",      "output",       "parse",          "load",
    "dump",       "serialize",    "deserialize",    "hash",
    "encrypt",    "decrypt",      "sign",           "verify",
    "connect",    "query",        "fetch",          "post",
]  # 32 calls

LANG_VOCAB = ["python", "javascript", "go", "java"]  # 4 languages

# Total: 30 + 32 + 4 + (depth + score + stealth + novelty + severity) = 90


class ThreatNet:
    """
    Neural threat classifier — built from first principles.

    Learns from the certified MISTCODER chain.
    Every certified finding is a training example.
    Every COVENANT verdict is a label.

    The chain teaches the model.
    The model teaches ORACLE.
    ORACLE guides PHANTOM.
    The Trinity becomes intelligent.
    """

    def __init__(self):
        SANDBOX.mkdir(exist_ok=True)
        self.vocab    = self._load_vocab()
        self.history  = self._load_history()
        self.weights  = None
        self.trained  = False
        self._init_weights()
        self._try_load_weights()

    # ══════════════════════════════════════════════════════════════════════
    # FEATURE EXTRACTION
    # Turn a kill chain into a 90-dimensional vector
    # ══════════════════════════════════════════════════════════════════════

    def extract_features(self, steps: list, score: float,
                          stealth: float = 0.5, novelty: float = 0.5,
                          language: str = "python",
                          severity: str = "HIGH") -> np.ndarray:
        """
        Convert a kill chain into a 90-dimensional feature vector.

        Dimensions:
          [0:30]  CWE one-hot    — which vulnerability classes are present
          [30:62] call one-hot   — which dangerous function calls are present
          [62:66] language       — python / javascript / go / java
          [66]    kill chain depth (normalised)
          [67]    score (normalised 0-10)
          [68]    stealth (0-1)
          [69]    novelty (0-1)
          [70:90] padding zeros (reserved for future features)

        One-hot encoding: a vector of zeros with a 1 at the position
        of each present feature. The model learns which positions
        matter for each verdict.
        """
        vec = np.zeros(INPUT_DIM, dtype=np.float32)

        # ── CWE one-hot (dims 0-29) ───────────────────────────────────────
        for step in steps:
            if step in CWE_VOCAB:
                idx      = CWE_VOCAB.index(step)
                vec[idx] = 1.0

        # ── Call one-hot (dims 30-61) ─────────────────────────────────────
        for step in steps:
            step_lower = step.lower().replace(" ", "_").replace("-", "_")
            for i, call in enumerate(CALL_VOCAB):
                if call in step_lower or step_lower in call:
                    vec[30 + i] = 1.0
                    break

        # ── Language encoding (dims 62-65) ────────────────────────────────
        lang_lower = language.lower()
        if lang_lower in LANG_VOCAB:
            vec[62 + LANG_VOCAB.index(lang_lower)] = 1.0

        # ── Scalar features (dims 66-69) ──────────────────────────────────
        vec[66] = min(1.0, len(steps) / 10.0)   # depth normalised
        vec[67] = score / 10.0                   # score normalised
        vec[68] = float(stealth)                 # stealth 0-1
        vec[69] = float(novelty)                 # novelty 0-1

        return vec

    # ══════════════════════════════════════════════════════════════════════
    # WEIGHT INITIALISATION
    # He initialisation — designed for ReLU networks
    # Prevents vanishing/exploding gradients
    # ══════════════════════════════════════════════════════════════════════

    def _init_weights(self):
        """
        He initialisation:
          W ~ N(0, sqrt(2 / fan_in))

        Why: ReLU kills ~half the neurons (the negative ones).
        He initialisation accounts for this by scaling variance
        so signals neither vanish nor explode through layers.
        """
        np.random.seed(42)

        def he(fan_in, fan_out):
            return np.random.randn(fan_out, fan_in) * np.sqrt(2.0 / fan_in)

        self.weights = {
            # Layer weights (W) and biases (b)
            "W1": he(INPUT_DIM, HIDDEN_1),
            "b1": np.zeros((HIDDEN_1, 1)),
            "W2": he(HIDDEN_1, HIDDEN_2),
            "b2": np.zeros((HIDDEN_2, 1)),
            "W3": he(HIDDEN_2, HIDDEN_3),
            "b3": np.zeros((HIDDEN_3, 1)),
            "W4": he(HIDDEN_3, OUTPUT_DIM),
            "b4": np.zeros((OUTPUT_DIM, 1)),

            # Adam optimiser moments (initialised to zero)
            # m = first moment  (momentum — running mean of gradients)
            # v = second moment (variance — running mean of squared gradients)
            "mW1": np.zeros_like(he(INPUT_DIM, HIDDEN_1)),
            "vW1": np.zeros_like(he(INPUT_DIM, HIDDEN_1)),
            "mW2": np.zeros_like(he(HIDDEN_1, HIDDEN_2)),
            "vW2": np.zeros_like(he(HIDDEN_1, HIDDEN_2)),
            "mW3": np.zeros_like(he(HIDDEN_2, HIDDEN_3)),
            "vW3": np.zeros_like(he(HIDDEN_2, HIDDEN_3)),
            "mW4": np.zeros_like(he(HIDDEN_3, OUTPUT_DIM)),
            "vW4": np.zeros_like(he(HIDDEN_3, OUTPUT_DIM)),
            "mb1": np.zeros((HIDDEN_1, 1)),
            "vb1": np.zeros((HIDDEN_1, 1)),
            "mb2": np.zeros((HIDDEN_2, 1)),
            "vb2": np.zeros((HIDDEN_2, 1)),
            "mb3": np.zeros((HIDDEN_3, 1)),
            "vb3": np.zeros((HIDDEN_3, 1)),
            "mb4": np.zeros((OUTPUT_DIM, 1)),
            "vb4": np.zeros((OUTPUT_DIM, 1)),

            # Adam step counter
            "t": 0
        }

    # ══════════════════════════════════════════════════════════════════════
    # ACTIVATION FUNCTIONS
    # The non-linearities that give neural networks their power
    # ══════════════════════════════════════════════════════════════════════

    def _relu(self, Z: np.ndarray) -> np.ndarray:
        """
        ReLU — Rectified Linear Unit
          f(x) = max(0, x)

        Why: Kills negative signals. Creates sparse activations.
        Prevents vanishing gradients better than sigmoid/tanh.
        The most widely used activation in deep learning.
        """
        return np.maximum(0, Z)

    def _relu_backward(self, dA: np.ndarray,
                        Z: np.ndarray) -> np.ndarray:
        """
        Derivative of ReLU:
          f'(x) = 1 if x > 0, else 0

        During backpropagation, gradients only flow back
        through neurons that were active (positive) in the
        forward pass. Negative neurons contribute nothing.
        """
        dZ        = np.array(dA, copy=True)
        dZ[Z <= 0] = 0
        return dZ

    def _softmax(self, Z: np.ndarray) -> np.ndarray:
        """
        Softmax — converts raw scores to probabilities.
          f(x_i) = exp(x_i) / sum(exp(x_j))

        Output: three probabilities that sum to 1.
          [P(CONFIRMED), P(NOVEL), P(DISPUTED)]

        Numerically stable version: subtract max before exp
        to prevent overflow on large values.
        """
        Z_stable = Z - np.max(Z, axis=0, keepdims=True)
        expZ     = np.exp(Z_stable)
        return expZ / np.sum(expZ, axis=0, keepdims=True)

    def _dropout(self, A: np.ndarray,
                  rate: float, training: bool) -> tuple:
        """
        Dropout — randomly zeros neurons during training.

        Why: Forces the network to learn redundant representations.
        No single neuron can become too dominant.
        Prevents overfitting — especially important with small datasets.

        During inference (training=False): no dropout, full network.
        """
        if not training or rate == 0:
            return A, np.ones_like(A)
        mask = (np.random.rand(*A.shape) > rate).astype(np.float32)
        return A * mask / (1 - rate), mask  # inverted dropout

    # ══════════════════════════════════════════════════════════════════════
    # FORWARD PASS
    # Input → prediction
    # ══════════════════════════════════════════════════════════════════════

    def _forward(self, X: np.ndarray,
                  training: bool = True) -> dict:
        """
        Forward pass through all 4 layers.

        X shape: (INPUT_DIM, batch_size)

        Returns cache dict with all intermediate values
        needed for backpropagation.

        Z = linear pre-activation  (W·X + b)
        A = post-activation        (ReLU(Z) or Softmax(Z))
        M = dropout mask
        """
        W = self.weights
        cache = {"X": X}

        # ── Layer 1: Input → Hidden_1 ─────────────────────────────────────
        cache["Z1"] = W["W1"] @ X + W["b1"]
        cache["A1"] = self._relu(cache["Z1"])
        cache["A1"], cache["M1"] = self._dropout(
            cache["A1"], DROPOUT_1, training)

        # ── Layer 2: Hidden_1 → Hidden_2 ─────────────────────────────────
        cache["Z2"] = W["W2"] @ cache["A1"] + W["b2"]
        cache["A2"] = self._relu(cache["Z2"])
        cache["A2"], cache["M2"] = self._dropout(
            cache["A2"], DROPOUT_2, training)

        # ── Layer 3: Hidden_2 → Hidden_3 ─────────────────────────────────
        cache["Z3"] = W["W3"] @ cache["A2"] + W["b3"]
        cache["A3"] = self._relu(cache["Z3"])

        # ── Layer 4: Hidden_3 → Output ────────────────────────────────────
        cache["Z4"] = W["W4"] @ cache["A3"] + W["b4"]
        cache["A4"] = self._softmax(cache["Z4"])   # probabilities

        return cache

    # ══════════════════════════════════════════════════════════════════════
    # LOSS FUNCTION
    # How wrong is the model? We minimise this.
    # ══════════════════════════════════════════════════════════════════════

    def _loss(self, A4: np.ndarray, Y: np.ndarray) -> float:
        """
        Categorical cross-entropy loss:
          L = -1/m * sum(Y * log(A4))

        Y: one-hot label matrix  shape (3, m)
        A4: softmax probabilities shape (3, m)
        m: batch size

        Intuition: penalises the model heavily when it's
        confidently wrong, lightly when it's uncertain.
        Perfect prediction → loss = 0.
        """
        m   = Y.shape[1]
        eps = 1e-8  # prevent log(0)
        return -np.sum(Y * np.log(A4 + eps)) / m

    # ══════════════════════════════════════════════════════════════════════
    # BACKWARD PASS
    # Compute gradients. This is where learning happens.
    # ══════════════════════════════════════════════════════════════════════

    def _backward(self, cache: dict, Y: np.ndarray) -> dict:
        """
        Backpropagation — chain rule applied layer by layer.

        Starting from the output error, we propagate the gradient
        backwards through every layer, computing how much each
        weight contributed to the total loss.

        dL/dW = how much did weight W contribute to the error?
        We update W in the direction that reduces the error.
        """
        W  = self.weights
        m  = Y.shape[1]
        grads = {}

        # ── Layer 4 gradient (Softmax + cross-entropy combined) ───────────
        # The gradient of softmax + cross-entropy simplifies beautifully to:
        #   dZ4 = A4 - Y
        # (predicted probabilities minus true labels)
        dZ4          = cache["A4"] - Y
        grads["dW4"] = dZ4 @ cache["A3"].T / m
        grads["db4"] = np.sum(dZ4, axis=1, keepdims=True) / m
        dA3          = W["W4"].T @ dZ4

        # ── Layer 3 gradient ──────────────────────────────────────────────
        dZ3          = self._relu_backward(dA3, cache["Z3"])
        grads["dW3"] = dZ3 @ cache["A2"].T / m
        grads["db3"] = np.sum(dZ3, axis=1, keepdims=True) / m
        dA2          = W["W3"].T @ dZ3

        # ── Layer 2 gradient (apply dropout mask) ─────────────────────────
        dA2         *= cache["M2"] / (1 - DROPOUT_2)
        dZ2          = self._relu_backward(dA2, cache["Z2"])
        grads["dW2"] = dZ2 @ cache["A1"].T / m
        grads["db2"] = np.sum(dZ2, axis=1, keepdims=True) / m
        dA1          = W["W2"].T @ dZ2

        # ── Layer 1 gradient (apply dropout mask) ─────────────────────────
        dA1         *= cache["M1"] / (1 - DROPOUT_1)
        dZ1          = self._relu_backward(dA1, cache["Z1"])
        grads["dW1"] = dZ1 @ cache["X"].T / m
        grads["db1"] = np.sum(dZ1, axis=1, keepdims=True) / m

        return grads

    # ══════════════════════════════════════════════════════════════════════
    # ADAM OPTIMISER
    # Adaptive moment estimation — the gold standard weight update rule
    # ══════════════════════════════════════════════════════════════════════

    def _adam_update(self, grads: dict):
        """
        Adam optimiser update:

        For each weight W with gradient g:
          m = β1 * m + (1-β1) * g          # update momentum
          v = β2 * v + (1-β2) * g²         # update variance
          m̂ = m / (1 - β1^t)               # bias-corrected momentum
          v̂ = v / (1 - β2^t)               # bias-corrected variance
          W = W - lr * m̂ / (√v̂ + ε)       # weight update

        Why Adam is better than plain gradient descent:
          - Momentum: doesn't zig-zag, builds up speed in flat regions
          - Variance: takes smaller steps for volatile weights,
                      larger steps for stable weights
          - Bias correction: accurate estimates from the first step
        """
        W  = self.weights
        W["t"] += 1
        t   = W["t"]
        lr  = LEARNING_RATE

        for layer in ["W1", "b1", "W2", "b2", "W3", "b3", "W4", "b4"]:
            g = grads[f"d{layer}"]

            # Update moments
            W[f"m{layer}"] = ADAM_BETA1 * W[f"m{layer}"] + \
                             (1 - ADAM_BETA1) * g
            W[f"v{layer}"] = ADAM_BETA2 * W[f"v{layer}"] + \
                             (1 - ADAM_BETA2) * (g ** 2)

            # Bias correction
            m_hat = W[f"m{layer}"] / (1 - ADAM_BETA1 ** t)
            v_hat = W[f"v{layer}"] / (1 - ADAM_BETA2 ** t)

            # Weight update
            W[layer] = W[layer] - lr * m_hat / (np.sqrt(v_hat) + ADAM_EPSILON)

    # ══════════════════════════════════════════════════════════════════════
    # TRAINING LOOP
    # ══════════════════════════════════════════════════════════════════════

    def train(self, training_data: list, verbose: bool = True) -> dict:
        """
        Train ThreatNet on certified chain findings.

        training_data: list of dicts:
          {
            "steps"   : ["eval_exec", "CWE-94"],
            "score"   : 8.5,
            "stealth" : 0.9,
            "novelty" : 0.5,
            "language": "python",
            "severity": "CRITICAL",
            "verdict" : "CONFIRMED"
          }

        Returns training history: loss curve, accuracy curve.
        """
        if len(training_data) < 3:
            print("[THREATNET] Not enough training data yet "
                  f"({len(training_data)} samples, need 3+)")
            print("[THREATNET] Scan more files to grow the chain.")
            return {}

        if verbose:
            print(f"\n[THREATNET] ═══ Training ThreatNet ═══")
            print(f"[THREATNET] Samples   : {len(training_data)}")
            print(f"[THREATNET] Epochs    : {EPOCHS}")
            print(f"[THREATNET] Batch size: {BATCH_SIZE}")
            print(f"[THREATNET] Architecture: "
                  f"{INPUT_DIM}→{HIDDEN_1}→{HIDDEN_2}→{HIDDEN_3}→{OUTPUT_DIM}")

        # ── Build feature matrix X and label matrix Y ─────────────────────
        X_list, Y_list = [], []
        for sample in training_data:
            features = self.extract_features(
                steps    = sample.get("steps", []),
                score    = sample.get("score", 5.0),
                stealth  = sample.get("stealth", 0.5),
                novelty  = sample.get("novelty", 0.5),
                language = sample.get("language", "python"),
                severity = sample.get("severity", "HIGH")
            )
            X_list.append(features)

            label = LABEL_MAP.get(sample.get("verdict", "NOVEL"), 1)
            one_hot    = np.zeros(OUTPUT_DIM)
            one_hot[label] = 1.0
            Y_list.append(one_hot)

        X = np.array(X_list).T   # shape: (INPUT_DIM, n_samples)
        Y = np.array(Y_list).T   # shape: (OUTPUT_DIM, n_samples)
        n = X.shape[1]

        # ── Training loop ──────────────────────────────────────────────────
        t_start       = time.time()
        loss_history  = []
        acc_history   = []

        for epoch in range(EPOCHS):
            # Shuffle data each epoch
            idx       = np.random.permutation(n)
            X_shuffle = X[:, idx]
            Y_shuffle = Y[:, idx]

            epoch_loss = 0.0
            n_batches  = 0

            # Mini-batch gradient descent
            for i in range(0, n, BATCH_SIZE):
                X_batch = X_shuffle[:, i:i+BATCH_SIZE]
                Y_batch = Y_shuffle[:, i:i+BATCH_SIZE]

                # Forward
                cache = self._forward(X_batch, training=True)

                # Loss
                batch_loss  = self._loss(cache["A4"], Y_batch)
                epoch_loss += batch_loss
                n_batches  += 1

                # Backward
                grads = self._backward(cache, Y_batch)

                # Update weights
                self._adam_update(grads)

            avg_loss = epoch_loss / n_batches
            loss_history.append(round(avg_loss, 6))

            # Accuracy on full training set every 20 epochs
            if epoch % 20 == 0 or epoch == EPOCHS - 1:
                preds    = self._forward(X, training=False)["A4"]
                pred_cls = np.argmax(preds, axis=0)
                true_cls = np.argmax(Y, axis=0)
                acc      = np.mean(pred_cls == true_cls)
                acc_history.append(round(float(acc), 4))

                if verbose:
                    bar   = "█" * int(acc * 20) + "░" * (20 - int(acc * 20))
                    print(f"  Epoch {epoch:>3}/{EPOCHS} │ "
                          f"Loss: {avg_loss:.4f} │ "
                          f"Acc: {acc:.1%} │ {bar}")

        elapsed = round(time.time() - t_start, 2)

        # Final accuracy
        preds    = self._forward(X, training=False)["A4"]
        pred_cls = np.argmax(preds, axis=0)
        true_cls = np.argmax(Y, axis=0)
        final_acc = float(np.mean(pred_cls == true_cls))

        # Per-class accuracy
        class_acc = {}
        for label_name, label_idx in LABEL_MAP.items():
            mask = true_cls == label_idx
            if mask.sum() > 0:
                class_acc[label_name] = float(
                    np.mean(pred_cls[mask] == true_cls[mask]))

        training_result = {
            "epochs"       : EPOCHS,
            "samples"      : n,
            "final_loss"   : loss_history[-1],
            "final_accuracy": final_acc,
            "class_accuracy": class_acc,
            "elapsed_s"    : elapsed,
            "trained_at"   : datetime.now(timezone.utc).isoformat()
        }

        self.trained = True
        self._save_weights()
        self._save_history(training_result, loss_history)

        if verbose:
            print(f"\n[THREATNET] ─── Training Complete ───")
            print(f"[THREATNET] Final loss    : {loss_history[-1]:.4f}")
            print(f"[THREATNET] Final accuracy: {final_acc:.1%}")
            for cls, acc in class_acc.items():
                print(f"[THREATNET]   {cls:12}: {acc:.1%}")
            print(f"[THREATNET] Trained in    : {elapsed}s")
            print(f"[THREATNET] Weights saved : threatnet_weights.pkl")
            print()

        return training_result

    # ══════════════════════════════════════════════════════════════════════
    # INFERENCE
    # Use trained weights to classify a new kill chain
    # ══════════════════════════════════════════════════════════════════════

    def predict(self, steps: list, score: float,
                stealth: float = 0.5, novelty: float = 0.5,
                language: str = "python",
                severity: str = "HIGH") -> dict:
        """
        Classify a kill chain using the trained model.

        Returns:
          {
            verdict     : "CONFIRMED" / "NOVEL" / "DISPUTED"
            confidence  : 0.0 - 1.0
            probabilities: {CONFIRMED: x, NOVEL: y, DISPUTED: z}
            method      : "neural" (trained) or "random" (untrained)
          }
        """
        features = self.extract_features(
            steps, score, stealth, novelty, language, severity)
        X = features.reshape(-1, 1)   # shape: (INPUT_DIM, 1)

        cache  = self._forward(X, training=False)
        probs  = cache["A4"].flatten()   # [P(CONFIRMED), P(NOVEL), P(DISPUTED)]
        pred   = int(np.argmax(probs))
        conf   = float(probs[pred])

        return {
            "verdict"      : LABEL_REVERSE[pred],
            "confidence"   : round(conf, 4),
            "probabilities": {
                "CONFIRMED": round(float(probs[0]), 4),
                "NOVEL"    : round(float(probs[1]), 4),
                "DISPUTED" : round(float(probs[2]), 4)
            },
            "method"       : "neural" if self.trained else "untrained"
        }

    # ══════════════════════════════════════════════════════════════════════
    # CHAIN DATA EXTRACTION
    # Build training dataset from certified blocks
    # ══════════════════════════════════════════════════════════════════════

    def extract_training_data(self, chain_path: Optional[Path] = None) -> list:
        """
        Extract training data from the certified chain.

        Reads sandbox/mistchain.json or chain_export.js,
        pulls every PHANTOM transaction,
        matches it with its COVENANT certification verdict,
        and builds a labeled training sample.

        The chain IS the training dataset.
        Every certified block is a ground-truth example.
        """
        training_data = []

        # Try chain export first (richest data)
        export_path = chain_path or (SANDBOX / "chain_export.js")
        if export_path.exists():
            try:
                content    = export_path.read_text(encoding="utf-8")
                json_start = content.find("const DATA = ") + len("const DATA = ")
                json_end   = content.rfind(";")
                data       = json.loads(content[json_start:json_end])

                for chain in data.get("chains", []):
                    nodes   = chain.get("nodes", [])
                    steps   = []
                    severity = "MEDIUM"

                    for node in nodes:
                        if isinstance(node, dict):
                            call = node.get("name", "")
                            cwe  = node.get("cwe", "")
                            sev  = node.get("sev", "MEDIUM")
                            if call: steps.append(call)
                            if cwe:  steps.append(cwe)
                            severity = sev  # use last node severity

                    if steps:
                        verdict = "CONFIRMED" if chain.get("certified") else "NOVEL"
                        training_data.append({
                            "steps"   : steps,
                            "score"   : chain.get("score", 5.0),
                            "stealth" : 0.75 if severity in ("CRITICAL","HIGH")
                                        else 0.45,
                            "novelty" : 0.5,
                            "language": "python",
                            "severity": severity,
                            "verdict" : verdict
                        })

                print(f"[THREATNET] Extracted {len(training_data)} "
                      f"samples from chain export")
            except Exception as e:
                print(f"[THREATNET] Chain export parse error: {e}")

        # Augment with oracle knowledge (adds variety to training set)
        oracle_path = SANDBOX / "oracle_knowledge.json"
        if oracle_path.exists():
            try:
                knowledge = json.loads(oracle_path.read_text(encoding="utf-8"))
                for key, entry in knowledge.items():
                    cwes    = entry.get("associated_cwes", [])
                    verdict = entry.get("verdict", "NOVEL")
                    conf    = entry.get("confidence", 0.7)
                    steps   = [key] + cwes

                    # Add multiple samples weighted by sightings
                    sightings = min(entry.get("sightings", 1), 5)
                    for _ in range(sightings):
                        training_data.append({
                            "steps"   : steps,
                            "score"   : conf * 10,
                            "stealth" : 0.7,
                            "novelty" : 0.3 if verdict == "CONFIRMED" else 0.8,
                            "language": "python",
                            "severity": "HIGH",
                            "verdict" : verdict
                        })

                print(f"[THREATNET] Total samples after augmentation: "
                      f"{len(training_data)}")
            except Exception as e:
                print(f"[THREATNET] Oracle knowledge parse error: {e}")

        return training_data

    # ══════════════════════════════════════════════════════════════════════
    # PERSISTENCE
    # ══════════════════════════════════════════════════════════════════════

    def _save_weights(self):
        """Pickle the weights dict — pure numpy arrays."""
        with open(WEIGHTS_PATH, "wb") as f:
            pickle.dump(self.weights, f)

    def _try_load_weights(self):
        """Load saved weights if they exist."""
        if WEIGHTS_PATH.exists():
            try:
                with open(WEIGHTS_PATH, "rb") as f:
                    self.weights = pickle.load(f)
                self.trained = True
                print(f"[THREATNET] Weights loaded from disk — "
                      f"model ready")
            except Exception:
                print(f"[THREATNET] Fresh weights — model untrained")

    def _save_history(self, result: dict, loss_curve: list):
        history = self._load_history()
        history.setdefault("runs", []).append({
            **result,
            "loss_curve_last10": loss_curve[-10:]
        })
        with open(HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)

    def _load_history(self) -> dict:
        if HISTORY_PATH.exists():
            try:
                return json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"runs": []}

    def _load_vocab(self) -> dict:
        return {"cwes": CWE_VOCAB, "calls": CALL_VOCAB, "langs": LANG_VOCAB}

    def model_card(self) -> dict:
        """
        A model card — standard ML documentation of what this model is,
        what it was trained on, and what its limitations are.
        """
        history = self._load_history()
        runs    = history.get("runs", [])
        latest  = runs[-1] if runs else {}

        return {
            "name"        : "ThreatNet v1.0",
            "type"        : "feedforward_neural_network",
            "architecture": f"{INPUT_DIM}→{HIDDEN_1}→{HIDDEN_2}"
                            f"→{HIDDEN_3}→{OUTPUT_DIM}",
            "parameters"  : self._count_params(),
            "trained"     : self.trained,
            "training_runs": len(runs),
            "latest_run"  : latest,
            "classes"     : list(LABEL_MAP.keys()),
            "features"    : {
                "cwe_vocab_size" : len(CWE_VOCAB),
                "call_vocab_size": len(CALL_VOCAB),
                "lang_vocab_size": len(LANG_VOCAB),
                "scalar_features": 4,
                "total_dims"     : INPUT_DIM
            },
            "training_data": "MISTCODER certified blockchain findings",
            "labels"       : "COVENANT constitutional verdicts",
            "limitations"  : [
                "Trained on Python findings only until multi-language scans run",
                "Small training set until chain grows beyond 100 blocks",
                "No guarantee of generalisation to unseen CWE classes"
            ],
            "strengths": [
                "Trained on constitutionally certified ground truth",
                "Improves with every scan — chain is the training loop",
                "Zero external data required — self-contained",
                "Full weight transparency — inspect every parameter"
            ]
        }

    def _count_params(self) -> int:
        """Count total trainable parameters."""
        if not self.weights:
            return 0
        return sum(
            v.size for k, v in self.weights.items()
            if k.startswith("W") or k.startswith("b")
            and not k.startswith("m") and not k.startswith("v")
        )