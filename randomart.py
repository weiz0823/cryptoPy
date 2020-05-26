offset = {
    0: [-18, -16, 16, 18],
    1: [-1, 1, 16, 18],
    2: [-18, -16, -1, 1],
    4: [-17, -16, 17, 18],
    8: [-18, -17, 16, 17],
    5: [0, 1, 17, 18],
    9: [-1, 0, 16, 17],
    6: [-17, -16, 0, 1],
    10: [-18, -17, -1, 0],
}
charset = " .o+=*BOX@%&#/^SE"


def visualize(octets, head=None, foot=None):
    """Return formatted string of randomart."""
    global offset, charset
    a = [0] * 153
    state = 0
    pos = 76
    for o in octets:
        for j in range(4):
            pos += offset[state][(o >> (j * 2)) & 3]
            a[pos] += 1
            # modify state
            state = 0
            x = pos // 17
            y = pos % 17
            if x == 0:
                state |= 1
            elif x == 8:
                state |= 2
            if y == 0:
                state |= 4
            elif y == 16:
                state |= 8
    a[76] = 15  # 'S'
    a[pos] = 16  # 'E'
    if head is not None:
        ss = f"[{head}]".center(17, "-")
        s = f"+{ss}+\n"
    else:
        s = "+-----------------+\n"
    for x in range(9):
        ss = "|"
        for y in range(17):
            ss += charset[a[x * 17 + y]]
        ss += "|\n"
        s += ss
    if foot is not None:
        ss = f"[{foot}]".center(17, "-")
        s += f"+{ss}+"
    else:
        s += "+-----------------+"
    return s
