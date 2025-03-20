---
title: "Easy - Two Sum [1]"
author: Tri Nguyen
date: 2021-05-04 22:14:00 -0600
categories: [Leetcode, Easy]
tags: [leetcode, easy]
---

## Description

<details style="margin-left: 10px">

<summary>View</summary>

<pre style="background-color: #2d333b; padding: 16px; border-radius: 6px">
- Given an array of integers nums and an integer target, 
return indices of the two numbers such that they add up to target.

- You may assume that each input would have exactly one solution, 
and you may not use the same element twice.

- You can return the answer in any order.

Example 1:

    ```
    Input: nums = [2,7,11,15], target = 9
    Output: [0,1]
    Output: Because nums[0] + nums[1] == 9, we return [0, 1].
    ```
Example 2:

    ```
    Input: nums = [3,2,4], target = 6
    Output: [1,2]
    ```

Example 3:

    ```
    Input: nums = [3,3], target = 6
    Output: [0,1]
    ```

Constraints:

    2 <= nums.length <= 103
    -109 <= nums[i] <= 109
    -109 <= target <= 109
    Only one valid answer exists.

</pre>

</details>

## Solution

- A naive approach would take O(n^2). By using a dictionary, this would narrow down to O(n), we don't need to access the list twice.

- My language of choice is Python 3, but I also attempted in Javascript and C++.

### Python 3

- Things I learn:
    - `for` loop with `range` is a lot faster than `while` loop.
    - `enumerate` is slower than the normal `for i in range(len(nums))` (by around ~8ms)

- <mark><b>Beats 94.48% of python3 submissions</b></mark> [(source)](https://leetcode.com/submissions/detail/488644950/).

```python
class Solution:
    def twoSum(self, nums: List[int], target: int) -> List[int]:
        di = {}
        for i in range(len(nums)):
            x = target - nums[i]
            if x in di:
                return [i, di[x]]
            di[nums[i]] = i
```

### Javascript

- I tried Javascript, simply because I don't like C and I naively thought Javascript performance is the same as C.

- Things I learn:
    - Obviously Javascript is slow, very slow. Best result is 68 ms.
    - Using `Map()` is slower than the `Object`/`dict` native. Time reduced from [80ms](https://leetcode.com/submissions/detail/488652119/) to [68ms](https://leetcode.com/submissions/detail/488652494/).

- <mark><b>Beats 98.32% of javascript submissions</b></mark> [(source)](https://leetcode.com/submissions/detail/488652494/).

```javascript
/**
 * @param {number[]} nums
 * @param {number} target
 * @return {number[]}
 */
var twoSum = function(nums, target) {
    var map = {};
    for (i=0; i<nums.length; i++) {
        x = target - nums[i];
        if(x in map) {
            return [i, map[x]];
        } else {
            map[nums[i]] = i;
        }
    }
};
```

### C++

- C++ is more modern in comparision to C and not much performance lost.

- Things I learn:
    - Learn `unordered_map`. Some syntax and bugs.
    - Removing 1 variable assignment cut the time from 8ms to 4ms. This was removed `int x = target - nums[i];`.

- <mark><b>Beats 94.89% of C++ submissions</b></mark> [(source)](https://leetcode.com/submissions/detail/488663903/).

```cpp
class Solution {
public:
    vector<int> twoSum(vector<int>& nums, int target) {
        unordered_map<int, int> map;
        for(int i = 0; i < nums.size(); ++i) {
            auto num = map.find(target - nums[i]);
            if (num != map.end()) {
                return {num->second, i};
            };
            map[nums[i]] = i;
        }
        return {};
    }
};
```