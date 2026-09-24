---
type: Attested Computation
runtime: python
parameters:
  - { name: day, type: string, required: true }
executor:
  resource: references/executor.py
  receipt: [result]
attester:
  resource: references/attester.py
---

# Computation

```python
result = day
```
