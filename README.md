# Priority Inversion Prevention Module

> A comprehensive real-time priority inversion prevention and deadlock detection framework for embedded systems and RTOS environments.

## Features

- **Multiple Priority Inversion Protocols**
  - Priority Inheritance Protocol (PIP)
  - Priority Ceiling Protocol (PCP)
  - Immediate Priority Ceiling Protocol (IPCP)
  - Stack Resource Policy (SRP)

- **Advanced Deadlock Detection**
  - Wait-for graph analysis
  - Resource allocation graph (RAG) support
  - Cycle detection using DFS and Tarjan's algorithm
  - Automatic deadlock resolution strategies

- **Schedulability Analysis Tools**
  - Worst-case blocking time computation
  - Response time analysis
  - Liu & Layland utilization bound checking
  - Protocol comparison and recommendation

- **High-Level Abstractions**
  - POSIX-like mutex API
  - Automatic protocol selection
  - Recursive and adaptive mutex support
  - Comprehensive statistics tracking

## Overview

Priority inversion occurs when a high-priority task is blocked by a lower-priority task holding a shared resource, while medium-priority tasks preempt the lower-priority task. This module implements several well-known solutions to bound or eliminate priority inversion.


## Getting Started

### Prerequisites

- **Xinu Operating System** or compatible RTOS environment
- Basic understanding of real-time scheduling concepts


## Implemented Protocols

### 1. Priority Inheritance Protocol (PIP)

When a high-priority task blocks on a resource held by a lower-priority task, the holder temporarily inherits the waiter's priority.

**Characteristics:**
- Simple to implement
- Handles chained blocking
- May have multiple blocking periods per task
- Worst-case blocking: sum of critical sections from lower-priority tasks


### 2. Original Priority Ceiling Protocol (OPCP)

Each resource has a ceiling equal to the highest priority of any task that may use it. A task can only lock a resource if its priority is higher than the system ceiling.

**Characteristics:**
- At most one blocking period per task
- Prevents deadlock
- Requires priority ceiling assignment at design time


### 3. Immediate Priority Ceiling Protocol (IPCP)

When a task acquires a resource, its priority is immediately raised to the resource's ceiling, regardless of whether contention exists.

**Characteristics:**
- Simpler implementation than OPCP
- No blocking analysis needed at runtime
- Slightly pessimistic (raises priority even without contention)


### 4. Stack Resource Policy (SRP)

Uses preemption levels instead of priorities. A task can only preempt if its preemption level is higher than the system ceiling of held resources.

**Characteristics:**
- Works with EDF scheduling
- Single stack for all tasks
- Prevents deadlock
- Optimal blocking bound


## Deadlock Detection

The deadlock module provides real-time detection using wait-for graphs

### Detection Strategies

- **Wait-For Graph**: Tracks process-to-process wait relationships
- **Resource Allocation Graph**: Full resource modeling
- **Timeout-Based**: Detects based on excessive wait times


## Schedulability Analysis

The analysis module computes worst-case blocking times and verifies schedulability


### Analysis Features

- **Blocking Time Computation**: Per-protocol blocking bounds
- **Response Time Analysis**: Fixed-point iteration method
- **Utilization Analysis**: Liu & Layland bound checking
- **Protocol Comparison**: Compare PIP, PCP, SRP blocking
- **Sensitivity Analysis**: Slack time, WCET margins

## Protocol Selection Guide

| Criterion | PIP | PCP/IPCP | SRP |
|-----------|-----|----------|-----|
| Implementation complexity | Low | Medium | Medium |
| Blocking bound | Unbounded* | Single CS | Single CS |
| Deadlock prevention | No | Yes | Yes |
| Works with EDF | No | No | Yes |
| Runtime overhead | Low | Medium | Low |

*PIP can have chained blocking, bounded by critical section count.

**Recommendations:**
- Use **PIP** for simple systems with few shared resources
- Use **IPCP** for predictable hard real-time systems
- Use **SRP** when using EDF scheduling or need single-stack
- Use **OPCP** when blocking analysis reveals benefit over IPCP



### Development Setup

```bash
# Clone your fork
git clone https://github.com/sravan1023/priority_inversion.git
cd priority_inversion

# Create a feature branch
git checkout -b feature/my-new-feature

# Make changes and test
make clean && make
./run_tests.sh

# Commit and push
git add .
git commit -m "Add feature: description"
git push origin feature/my-new-feature
```

## Known Issues

- SRP implementation assumes static preemption level assignment
- Deadlock detection has O(n²) complexity; not suitable for very large process counts
- No support for read-write locks with multiple readers yet


## References

### Academic Papers

1. Sha, L., Rajkumar, R., & Lehoczky, J. P. (1990). **Priority Inheritance Protocols: An Approach to Real-Time Synchronization**. *IEEE Transactions on Computers*, 39(9), 1175-1185.

2. Baker, T. P. (1991). **Stack-Based Scheduling of Realtime Processes**. *Real-Time Systems*, 3(1), 67-99.

3. Liu, C. L., & Layland, J. W. (1973). **Scheduling Algorithms for Multiprogramming in a Hard-Real-Time Environment**. *Journal of the ACM*, 20(1), 46-61.


## Acknowledgments

Special thanks to:
- The Xinu Operating System development team at Purdue University
- Dr. Lui Sha and colleagues for pioneering priority inheritance research

## License

This code is part of the Xinu educational operating system.
