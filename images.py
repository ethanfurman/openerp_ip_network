from openerp import tools

black = dict(image=False, image_medium=False, image_small=False)

# red light
red_light = '''\
/9j/4AAQSkZJRgABAgEASABIAAD/7gAOQWRvYmUAZIAAAAAB/9sAhAAMCAgICQgMCQkMEQsKCxEVDwwMDxUYExMVExMYEQwMDAwMDBEMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAQ0LCw0ODRAODhAUDg4OFBQODg4OFBEMDAwMDBERDAwMDAwMEQwMDAwMDAwMDAw\
MDAwMDAwMDAwMDAwMDAwMDAz/wAARCADhAOEDASIAAhEBAxEB/90ABAAP/8QBPwAAAQUBAQEBAQEAAAAAAAAAAwABAgQFBgcICQoLAQABBQEBAQEBAQAAAAAAAAABAAIDBAUGBwgJCgsQAAEEAQMCBAIFBwYIBQMMMwEAAhEDBCESMQVBUWETInGBMgYUkaGxQiMkFVLBYj\
M0coLRQwclklPw4fFjczUWorKDJkSTVGRFwqN0NhfSVeJl8rOEw9N14/NGJ5SkhbSVxNTk9KW1xdXl9VZmdoaWprbG1ub2N0dXZ3eHl6e3x9fn9xEAAgIBAgQEAwQFBgcHBgU1AQACEQMhMRIEQVFhcSITBTKBkRShsUIjwVLR8DMkYuFygpJDUxVjczTxJQYWorKDByY1w\
tJEk1SjF2RFVTZ0ZeLys4TD03Xj80aUpIW0lcTU5PSltcXV5fVWZnaGlqa2xtbm9ic3R1dnd4eXp7fH/9oADAMBAAIRAxEAPwD1VJJJJSkkkklKSSSSUpJJVsjOookE7n/uN/ikpsoduRTT/OPDfLv9yxMzrThIc8Vj9xmrll2dRe4+wRP5ztSkp6Szq1I/m2l/mdAqtvWn\
juyv8SsP1rHOG5xM/cmtHtB8Ckp07Ouwdbnf2W/7FXd9YmAwbLTHh/vWVdyCqtn0ykp2x9Z6p+ncP9f6yPX9ZaidL3j+s3/YVyf53zRWcpKezp6+HcW12eR0P8Fcr6vWf5xhHm3ULhGhWKLbaxLHlvwKSnvasrHu0Y8E+B0P4oy4Wvq1zDFjQ8DuNCtbB69MNZZP/B2c/wB\
lJT0iSqY/UqLoa79G/wADx8nK2kpSSSSSlJJJJKUkkkkpSSSSSn//0PVUkkklKSSSSUpQstrqYX2ODWjuVDKyqsavc8yT9Fo5JXKdZ6/scQ4h935tQ+izzekp1Oo9bDWmHejVwD+c74Lncjq9tpLKv0bD3/OP/kVmPybcl3qWuLn/AJP6qRtYxhsscGNYJc5xgAeJJSU263\
Ekg6nlGD2sYXPcGNbqXOMADzcVx3VPrxRSTV0xn2i3j1XA7Af5DPp2Ln8mzrHVX+p1C923kMOgH9WpsMamynGOsjTLh5fLmPDjgZ+Ww/vSe6zvrt0DC9ouOTYPzaBuH/bjttf/AEljZf8AjLybZZgYDR4OtcXn/Mr2f9Uufq6djV8t3nxdr+CstYGiGgAeA0UMuZHQW6eL4\
JkOuTIIeERxn/uWd31r+tmT9FwpHgytrf8Az5ucgHq31peZdlvB+LR/1IRYTQmfeZdg2Y/BMA3lM/WI/wC5QftL6zN1+1OPzafyhEr+sP1noMl/qDwcxjv+pCnCaEhzMuwRL4Lg6SmPrH/vW3j/AF7zqobmYbH+JYXMP/S9RbeD9duiZIDbHPxX+Fo9v/bjN3/SXLloIg6j\
wKBZhY7+WbT4t0UkeYHUfY1cvwaY1x5BLwmOH8fU+jMuqurFlL22Mdw9hDh/nNUXnSF5tSzqOBZ6uBe5h8GmJ/rN+g9bnTvrqdwp6rXtdx6zB/58q/8AIKWM4y2Nudm5fLhNZIGPj+if8J7XH6vkY0Mf+lr/AHXcgfyXLo+l9ea9sVu9Rg+lW7R7VxFeRTkVi+l7bK3cOaZ\
CTbrKni2txY8cOGhTmJ9WoyKr2b63SO47j4oi4bo31iL3tZY4VZHAd+a/y/rLsMPNrym/u2D6TP4hJTZSSSSUpJJJJSkkkklP/9H1VJJJJSkHKyq8are7UnRre5Knbaymt1jzDWiSuL+sv1gdQJaf1i0EUs7Mb++UlMOv/WB1VhrY7dlO5Pasf+SXM73OcXklxdqSdSVW9V\
znF1hLi4yXHUyVV6n1erptMmH3PH6Ov/v7v5CSm7n9Vxem1ete7U/QrH0nfD/yS5TN6h1LrlnvPo4gPtrH0R/6VehV0ZGfccvNcXbtQD3H/fa1oNaAAAIA4AVfLnEdI6nu6/IfCZZQMma44zrGG0p+f7sUOPiU0D2D3d3HlGhSATwqhkSbJt6HHhhCIjCIjEdIsYTwpQlCF\
svAxhNCJCaErVwMITQiQmIStaYIiExCIQmITgWOUERCHbRVcIsbPge4RyFEhOBI1DBkxiQMZASidwdQ06Ls/pFvrYry6o/TYdWkf8Iz/v66fpnWsbqbPb+juaJfSTqP5TP32rCVO/FfU8ZOISyxhmG6H4sVnHmvSX2uLznwzhByYNR+lj6j+49m50nyC6DoP1hd6jMfIftt\
GlNx7/yLFxHSetNz2ejbDMlo1HAcB+c3/wAir5d4KdyX2PBzW5TNfba36bf+/BWl599Wev2WObj2v/WqhLHH89o/Nd/LXd42QzJpFrO+hHgfBJSZJJJJSkkkklP/0vVUklU6llfZsYlp/SP9rPj+9/ZSU4/1j6xVj1WPcf0OPyB+e/8ANYF5pk5luZkPyLj+ksM+QH5rW/1\
Ve+tfVjk5n2Sp004x98cOs/O/7b+gsX1WBpc87QBJJ4gJKZZmfXhY5ts1PDG93O8FgY9NubcczLO7cZaDwf8AzBqVtj+q5u4yMerRo/k/+SsWi1oAAAgDQBV8+Xh9Mdzu6/wn4eMp9/KLxxPoif05Dr/diuApAJAKQCpkvTRioBPCcBSATSWUQYwnhShPCFsggwhNCJCaEL\
VwMIUSEQhMQjawwRkKJCIQokJwLHKKMhRIRCFEhOBYJRREJlMhRKeGCQppZeO5jhlY5LbGHcY8vzgtrpvU25tEmBczSxv/AH9v9ZUVRebOn5Tcmn6BMFvbX6TFZw5L9J+jifE+SEbz4xp/lIj/AKf/AHz07Ln02NtrcW2MIc1w5BC9F+rHXm5NLbzoHezIZ+6799eYV5Fdt\
bbazua8SFp/V/qx6fntNhjHuhlw7D9yz+w5TuS+08p1n9Hy/Wo9Jxl9XHm381aCSlJJJJKf/9P1Vch9b+sjEovyAf5kelSPGx2n/Vf9Qupy7xj41lx/Nbp8fzV5F9eupF+VTggyKh6tv9d/0f8Aof8AVpKef3lxLpkkyT4kqh1fKIrbjM+nZq6PDsP7SsCxvMxGpWfhg5Wa\
/Ifq1mo/IxNnLhiZHoy8vhObLDFHeZryH6Um9h44x6Qz846vPmrICYBSAWdKRJJPV7TDijCEYRFRiOEMmgTroEdraA4Q4nyIQWiTHirNVJbY0uggHUDUqKZ8WyAARZpGWsnQlFYzHcf0ji3yAlQcyHH4o5xzY/2QBp9LRMkR3rxZwBW9eLOmrpznubdc9lYjY4NkmfpSi+h\
0cZFbBk2eg4H1bNnuaR9Da387ckzpd1gDWuYCOS5wA1/dRm9Dyd7ad9W+yS128bRH77vzVBLJC9cpGm3p/wAb5f8ACYZTxAm8xjodLj/j/L/hscrG6CyprsXLttsLwHNdXtAYfpvn95qsW4P1SFNjquo5DrQ0mthpgF0e1pKjZ9XsvHYLLLKHNcQwBlgcZdwSP3Ud31P6iy\
t1rr8UtrBcQLgSQNfaIUuGQI9J9zTc/wDoPCwyyYKjfNzGuhvH+s/q/wA21acT6svx635GdfXe5oNlbapa13drXfnKvVj9Ed6vr5VtYa8inbXO5n5r3/uuVxv1Wzrq23suxmssG5rXWgOAP7zfzUH9gZVu7ZZS30jsdusAkjuz95ijnOA3ymG37vp/5qePD6q5mR17w/V6/\
L8jWsxuiD6GVafjXCq2VYI+ha8/FsK5Z0PKZzZSfhYCqluBazlzD8HSn45RO2Uy/wAX/vV8eE7TM/Ov2Nctpn6Rj4ILgJMajsUc0umJH3oLhBIPZWInxtbkj4UjIUCEQhQKkDVmGCjbW22t1buHflUymTga1YZREgYkWCKI8Gt0rIdTa/Es8SWfEc/5y0nGeVkdQY6uxmSz\
QgiT5j6KvsubZW2ydHCVehLiiC8tzOE4c0sfQH0/3T8r6b9Set+ti1Oe6bMY+jd5t/Mf/mf9Qu+XiP1P6j9m6uKHGK8tprP9Ye6r/wAivY+l3+vhMJ1cz2O+I/8AMU5hbaSSSSn/1PQevXbaK6pj1HSfg1eGdXznZvVMrJ5bZY7b/VHsZ/0Gr1v665v2bGyrQYOPjOI/rOB\
2/wDfV4mHEDlJSsu7bQ4DQu9qsdNq9PGae7/cf++rPyibH11+J/LotpjQ1oaOAIHyVfmpekR76uz8CxXlyZT+gBEec/8A0VmFIKIUwqRemgGQCu9NYBnUmz2MDtXO0A08VTbotPodYyOrY1No31vfDmnUHQqDMaxzPQRlf2MmSxjmegjInvt0alo/TPjjcYPzVzqLA/MPo/\
pG7Ww5uo48lXyGhuTawCGtscAPIFaPXKW4nUnVUD0mBjCGt0ElqjlL1wHUxkR/zF5lU8Y/SMJkdtPbR24lrsPFDK3Od79wAJI1/ORKOnZRwb2+g/eXN2t2mSO+0I2RZdV0zAtre5r7fV3uBgna6GyrGHk5buk5d/rP9Sp7Ax86gE+6FXlkycFiv5zh1vf3eFrSy5OCxw17v\
Drfze9wf9Jp4HS8xtrjbjWMaWOAc5hAJP0W6hDp6J1UWMc7BvDGuBc41OAAnlx2rT6Rm5+RkPruyLLGNqe8Nc6QHNHtd/ZVbF631izIpqfnXOrse1r2l5ggmC0qSEzxZBPcRHy/4S33eZ4sgHt6RiZWZ/L6vlaeZ0jqLsm19eJc+tziWubW4gjxa6E/UOm5hbj+nj2O21ND\
9rCYd+66B9JWeqdW6pRn5FFWXayqt5axgcQAB2Cl1rOzqG4XpZD2etjtssh0bnHlzkOPJeHh4fUOt/ur4ZOYJw37fqB4fn/c/ScR2Bmt5osHxYf7kF+Pc36Vbh8QVZf1HPd9LIefi4oD8i930rHH4lWYnJ14fpbZIyfpcP8Ag2gLHeBQyEUvfPJQ3a6lTC2LIB0RlQKIVAp\
4aswjKZSKintc7o8mv1aHs7xI+IVbp9s1Fh5YdPgVdWbV+hzLKxwZA/6oKxy8t4/Vx/jGL+byjxgf+lH/ALt0ar303Mur0fU4PafNp3L2/wCrOY29h2n2XMbcz5j/AMyXhBcV6v8A4vM31On4BJkt30O/slzW/wDfFYcd75JJJJT/AP/Vuf4y8ot6d1DX6b66vxZ/5FeThw\
7Fejf40Lf1O8eOYAfl6n9y8z3hJSfH/SZ1YOsGfuG5bYWL06DmA+R/ItoKnzJ9Y8no/gca5eR75D+EYswphQCmFVLuwZt5Wp0KkZnVsXGcTULX7S+v2vGh+g5ZbYnXha31fFzus4jcItryS/8AROtEsBg/Ta1RyF6d9F2f+ZyHqITqX6MPTvJqZDNuTbXJO2xzZPJgxqtTr\
eMOn9Tfjtc64NYx2+47ne5u76WizMkPGXcHkGz1HbiOJ3HdH9pa31ibk19Xe3qLmW5Gyvc6kbWRt9kB38lRyjpfbT7VSJ9zCL0OPITH9KX816h/dT3vNHS+n5Aa15yPVljxLW7Xbf0bfzd35yvYGW53SMvJ9GoGp7Ghgb7DuP57VUyTU3o/THZMux3C77O1mjxDh6nquP0v\
d9BXenvwf2FnPa14xm2V+s0kbyZ9npuVXJihsccj+lp/j/vOdmo4gTEyPv8ADxDbh+88PB/e/wAmm6Rn2X5D63Y9DA2p75YyCdonadfoqpi/WO2zIpoODhtFr2sLhV7hJAljt30ld6Dd0mzKsGPXa2wUWFxe4EbI94H8pUsG/wCqjszHDMfLFptYK3F7S0O3Dbu1U2GFC4/\
q+IcPq/l/WYeHHx5r5ecuGMSKHyfP6j60fV+vW43UMnGGHivFTy0PfXLjHd7t30kuu9VfjswSMbHf6+My072Ttn8yvX2sT9ds+rY6rmC6nKdcLXCxzHtDS7vsBRPrK/oba+m+tXe6cOs1bXAQz81r/wCWhLDDrAy9vTT9L9H0+pmxDFfK/qJ+qJ4tPn/V9PW87b1d7/8AtN\
jj4M/2qrbluf8A4OsfBsK1bZ0X8yq8fFwVS12EfoNePiQpMYj0xyj5/wC+6kRAbY5Q/vf+jIDYZmB9yC7UkoxNc8GEF0SY4ViK3J5sCoFTKgVIGrNgVFSKinhry3Us3M9ma13G4A/99Wks7qel1Z8v4qXAfX9HP+Kxvlif3ZRP/csi4dyvQP8AFtlRhuaD/M5TT/nBh/76v\
NvWZ5rtv8XN/wCjzQOA+p34O/8AIq288+3JKO5JJT//1qn+M1pOPkDwzJ+/1P715x6fmvUf8ZVM19QZ3bbXZ95b/wCTXme0JKZ9N0zAPI/kWyFi4p2Z1fgTH3iFshU+ZHrHk9H8Dl/R5DtkP/RikCmEMKYVYu5ApG6mFqdDtdidWxsippyH1vltLPpOMfRaspvgtPoj24vV\
cbIvOyqt8vcewg+ChykiEiNSASI/vLs2uKYveEhwfv8Ap+VDkPLsm15G0usc4tPIJM7Vp9byH53U333VnEeWMHpWfSENjd+b9JZWQ7dk2vGrXPcQfImVpdbtbndSdfin1KyxgDhpqGwfpKKUjxRGwMSTL90jh0XkfrMRrbHMcf7n816P3fV/3Ddvay/pfT8d9jaWUerstd9\
F+5wcdn9RXcHGob0XNxvtdZZc+suu/NYWnRr/AOuszJoyL+mdPoqYXWUC31GiNNzgWqxh9N6gOjZmP6J9W19ZY2RqGn3d1VnkPDfu8J4+GvR8vucHF/i+po5BH2gPdEP13Fw+j/xRxe56v/DXR6F0/Fx8qyxnUKbi6mxhY3kBw1edfosQMLoHTmZNFo61jOdXYxzWDlxBB2\
j3fnIPQuj9Voy7H24zmNdTYwEkcuHtHKBg/Vb6wNyabnYb2srsY5xJaIAIP7ynxSNzH87wxBB/evi/cYpGInmP32MbjHX9R+s+f0trrHRcG7qOTc/q2PW6yxznVu5aT+a73J+vdOxchmDvz6avRxWVt3fngf4Rmv0XKn1f6v8AW7eo5NrMR7q32FzXS3UH+0pdb6R1O9mF6\
VDnejjMrs1Gjhy3lMnkIOO8nt8Y1vh9Hp/rr8ZF8t/S4nhif8z+r/V7f+jOXb0zFbxn0u+H+9VLcapnF7HfBFs6R1Jn0qCPmP71Xsw8ln0qyPuVjGR/nRL/ABP2OgJX/lfc/wAT/uERY2fphBdoSOUQ12cRqhO0MHlTx87W5PKmJUCpFQKkDVmWJUU5TJ7XO6lndT1uYP5P\
8VorNzjuzGt8AB/35S4Pn+jQ+KmuWPjKI/7pB6A8V2P+L5mxuZrO59Q/6tctsau0+oFI2Ed7sljR8to/78rbzz7NtSU0klP/19L/ABi4u6+9vbIxtw+LJH/fGrykNHYL2/6+4u7GxssCfTea3nyeJb/0mLxrJx3U5FtUfQcQPh2SU52RNdtdvh/AythpBAI4OoWdmUk0F3d\
hn5KzgW+pjMPdvtPyVfmY6A9tHY+CZankxn9ICY/wd/8ApNsFTBQwVIFUyHo4SSgq90h+3qWOTqA7v8Fngqxhv2ZNbvAqLJG4SHcEM3zRI7gj7WVzpyLD/LP5Vd6xZuz3Fug2t407LOe6bHHxJ/Kj5lm+8u8h+RMMfVA9okf9Flj80T+7Ex/xuH/vW3k3H9n4QBII9SYP8p\
Tx8h46XlN3ukvZBk+Ko22Tj0t/d3fiU9dsYtrP3i38FH7fpqv0+L/xziVwDgAr9Pj/APHONvdIybG5LyXuj0njk+CrYuTcMmk+o/R7fzj4hDxLdljj4tI+9CrdFjD4OB/FO4PVM9wB/wBJdwR4pmh6ogfZxNvqOTc7OvIsdBee5ROq5Fjm4kPdpQ0HUqjkv3Xvd4klSy7N4\
q/ksASGPXH/AFR/3KzgA9vQegV/zeFCbbD+cfvKgXuPcpiVElTgIkQok+KgSnJUCU4BgnJYlQKclRJTw15lZMkknMKlmt/S5z3jUNn8Par99np0vf4DT49lT6dWdjrDy4wPkrHLjc/RyPjGTTHj85n/AKMf+6SlviF6D/i8xZuwGAcvfe74Dc4f9S1cKGOcQ0akmB816t/i\
+wg2+26PbjVNpafN3P8A0a1Ycd7lJJJJT//Q9G67g/b+k5OMBL3MLq/67fez/pNXiHV6Cb23AQHiHfEL35eS/XfpH2Lqt9TWxVeftFHh7vps/sv3pKeO9JhaWu1BEH5qhgudj5L8Z/c6fEf+SatYNA4Cz+rYzmFmWzQtIDv++OTZx4okd2Xl8xw5YZB+idfGP6QbgKmCq+P\
cLqm2DvyPAowKz5CjRevxZBKIlE3GQsHwSAolR/SN+KCCi4+tzB5pkhofJswnRBZE+4/FTsPv1QXH3H4ouRpaR5BN6jyZRk6d1yfY35pwTsKi/wDmqz4z+VOz+ZefMJvT6/tX+71+i7CZ08EwOoSo1cf6pUGH3t+IRrdXufgyefcUrD9H4JrTFjh5p79BX/VCQ6LTk/FGSo\
kpiUxKeAxSkolQJTkqBKcAwSkolRKRKZPYZG1JJJnvaxhe7RrRJSWkgAk6AalpdSsJ2UN1LjJH4NCu1UNrqbX+6IPx7qr02l+Tkvyn/RYfb8e3+Y1ahaO4V7HHhiB9ry/N5/ezSn02j/cj8q/TqN2W1x1bX7j8vor2b6nYJxOh1PcIsySbneMO/m//AANrV5l9WelOz8+jD\
aD+sPBsPhW33PP+YvZ2MaxjWMG1rQA0DsBwnMDJJJJJT//R9VXO/Xfox6l0k30tnJwptrjlzP8ADV/5vv8A7C6JJJT4G9o3S3UO1SdjssY5lolrhBC6T67dAPRupm+lsYOYS+qOGP5sp/7/AF/yFhNaCAeZ4SU80A/p2W6i3+adq13l+a//AMktAFXuo9Nbn4+3RtrNanHx\
/dP8lyw8TIfU84mQC17DtE+X5pVfPiv1D6ut8L53grBkPpP83Lsf3HQBU2WOY4OboRwhApwVVId+M0u4kz4qTrHPO53KECnlCmQTSmxxaGnhvHzTixwaWjh3PyQpSlDhXcQSsscwy3nhRDiCCOQoSlKXCnjZveXOLjyeUn2OcAD+aIHwQ5TSlwrTJkSokpiUxKcAxymolRJ\
SJTI0xGVqSSSRWqVHKe/KvbiUe4k+74/+RYiZuUax6VWtrtNO0/8Aflp9J6WcOr1bR+sWD3fyR+5/5NWMOP8ASP0cn4nzgo4MZ/2h/wDUf/fM6MVmPS2qvho1Pie7lMMl0O47o7mg68LQ+rPRLOu9UZitkY7Pfk2DtWPzf69v0GKw4z2v+Lvo3oYb+q3NizJGyie1QP0v+u\
vH/QXYqNdddVbaq2hldYDWNHAAENaFJJSkkkklP//S9VSSSSU0es9JxesdOtwMkeywS145Y8fQtZ/KYvHMzDyuj9Rs6dnt2vrOjvzSD9C1n/BvXuKwPrf9Vcf6xYMCKs6gE415/wDPNn/BP/6CSnzNrN2vZUOsdEbns9WgBmSwaHgOA/Md/wB9cjVWZPT8t/TOpMNF1Lth3\
fmnwP8AId/g3rTa3sElPEUZT63nGygWWsO2Xaa+D1dlb3VehY3U2f6PJaIZcP8AqbP3mrlr6s/pF32fNYdn5jhqCPGt/wCcoMmG9Y/Y63JfE+Gsec6bRyf9/wD983JTyhV212t3Vu3D8imqxHd2o5AQDEgg7EM5SlQlKUKXcbOUpUJSlKk8bKU0ppTJUtMl5STJIotSSSZ7\
2MbueQ0DuUkEgCyaA6ldVcrNFZ9Kn3WnTTWP/MlEXZWdaMbBY5zndxzHj/Iauh6T9X6cAC2+Lco/nfmt/wCL/lfy1Yx4esvscnnPiYo48B88n/qv/vmn0fojqIy8wTe7VrDrtn853/CLVI8FYc2NCs7Lynm0YmIDbfYQwBgkydAxkfSerDjL7LsvKrwsNhtvucGNa3u49v8\
Aya9e+q/1ep6D0xuMIfkWe/JtH5z/AAb/AMHX9GtZX1G+preh0fbs4B3U72we4qYf8Ew/6R3+FeutSUpJJJJSkkkklP8A/9P1VJJJJSkkkklPO/W76nYX1jxt0ijqFQIoyQP/AAK79+r/AM9ry03dQ6BmO6Z1ip1ZZ9Fx19vZ9b/8NSvdFmde+rvS+v4n2XqFW6JNVrdLK3\
H8+p/+rElPnVBY+sWVuD2vEhw1BClkYePlUGjJrFtbuWu/77+65ZnWfq19ZPqbc7Iq/XelEz6zQS0D/uxUPdjv/wCF/m1Y6T1/p/UCGB3o3/6J55P/AAb/AKL0lOH1L6k5NDjf0iwv7+g4w8eTH/Rs/tLEdlZOLYaM6l1djeQRtd/muXqNbdZPZLIwcPNq9PMpZezsHgGP6\
rvpNTZQjLcM2Hmc2E/q5ED93eP+K+bV5FFv0HgnwOh/FEXTZ3+Lvpl8vwrrMV54Yf0jP+lts/6ayMn6hfWXEl2NbXksHAY/af8AMu2tUMuX/dP2ulj+MdMuP6wP/cy/79oJKF3TvrNi/wA9g2nzDC4ffUgGzqjdH4bwfNjwmHBPwbMfivLHcyj5x/71tJKoL+on6OK8/wBh\
xRK8br9+lWHZ8fTI/F6XsT8FH4ryw6yPlH/vk6hZfTX9N4Hl3+5WKfqp9Y8qDc5tDTzveJ/zad618L/F/hsh+bkPvdzsrGxv+cdz08cv3P2NbJ8YH+Tx/WZ/7mP/AHzy7s99jxVi1mx7tG6Ek/1WNWngfVHqOY4XdTecevn0+bD/AGfo1LssTpmBgM24dDKfFwHuP9ax3vc\
ivHdTRxxjsPq52fm82b55afuj0w/xXNxOnYmDT6OLWKx3PLifF7/zlN4EEuMAck9kPqfVsHAH6Z829qW6vP8A5D+0s/pnSvrH9cr9uHX9n6e0xZe6RUP7X0si3/g605gRX5+RnZDendKrdffadrTWJJP/AAf8n96xekfUr6iUdCY3Oztt/VHjnllIP5lP71n+kuWl9Wfqj0\
r6t4+3Fb6uU8Rdl2Ab3/yR/oq/+DYtxJSkkkklKSSSSUpJJJJT/9T1VJJJJSkkkklKSSSSUs5rXNLXAOa4QQdQQVw/1l/xV9H6nvyelEdNzD7trRNDj/KpH81/1n/ttdykkp8Qyq/rv9Ujs6jjHJwWaC7WyqP5OSz31f8AXlodO+u3RMoNZe44dh7Was/7dZ/39evEBwIIk\
HQgrmetf4ufqn1cussxBi3u5uxT6Tp/lMA9F39qpJTl411OQA+ixtzDruY4OH/RRrT7Y8SuezP8TfU8Sw3dB6tB5Dbt1Tv+3sffu/7aVC3pH+Njpmhqdm1t4LTXfP8A7sJKemuOoVWxx3nVcvZ9Y/rnjGM7ozwW6Emi5n/mKrv+vOY1x9Xp20+Bc4f9UxJT00ndz3RGHVcg\
PrrkvP6PAk+Ac4/kYjM6/wDWrII+x9Ie4njbTa//AKlJT1rUT1GV177HBjRy5xAH3uXNU9H/AMaPUjFeI/EYeS4V0R/28fVWjif4n+v5zxZ1zqjWDktYX3v+E2+lW3/ppKQ5/wBbOi4hcG2/aXj82nUfOz+bWbjZX1t+s7zT0TEeygna61ujR/xmXZtrb/1tei9G/wAV31S\
6WW2Px3Z9zfz8o7xPlS0Mp/zmLrK666mNrqY2utohrGgAAfyWtSU+ffVz/FJhY5GV9YLft2RO77OwkUg/8I8/pcj/AMDYvQKaaaKm00MbVUwQytgDWgeDWtU0klKSSSSUpJJJJSkkkklKSSSSU//V9VSXyqkkp+qkl8qpJKfqpJfKqSSn6qSXyqkkp+qkl8qpJKfqpJfKqS\
Sn6qQbuV8tpJKfqOr6SOvlVJJT9VJL5VSSU/VSS+VUklP1UkvlVJJT9VJL5VSSU/VSS+VUklP1UkvlVJJT9VJL5VSSU//Z'''
red_light_small = tools.image_resize_image(red_light, size=(64, 64))
red_light_medium = tools.image_resize_image(red_light, size=(128,128))
red_light_normal = tools.image_resize_image(red_light, size=(256,256))
red = dict(image=red_light_normal, image_medium=red_light_medium, image_small=red_light_small)

# yellow light
yellow_light = '''\
/9j/4AAQSkZJRgABAgEASABIAAD/7gAOQWRvYmUAZIAAAAAB/9sAhAAMCAgICQgMCQkMEQsKCxEVDwwMDxUYExMVExMYEQwMDAwMDBEMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAQ0LCw0ODRAODhAUDg4OFBQODg4OFBEMDAwMDBERDAwMDAwMEQwMDAwMDAwMDAw\
MDAwMDAwMDAwMDAwMDAwMDAz/wAARCADfAOEDASIAAhEBAxEB/90ABAAP/8QBPwAAAQUBAQEBAQEAAAAAAAAAAwABAgQFBgcICQoLAQABBQEBAQEBAQAAAAAAAAABAAIDBAUGBwgJCgsQAAEEAQMCBAIFBwYIBQMMMwEAAhEDBCESMQVBUWETInGBMgYUkaGxQiMkFVLBYj\
M0coLRQwclklPw4fFjczUWorKDJkSTVGRFwqN0NhfSVeJl8rOEw9N14/NGJ5SkhbSVxNTk9KW1xdXl9VZmdoaWprbG1ub2N0dXZ3eHl6e3x9fn9xEAAgIBAgQEAwQFBgcHBgU1AQACEQMhMRIEQVFhcSITBTKBkRShsUIjwVLR8DMkYuFygpJDUxVjczTxJQYWorKDByY1w\
tJEk1SjF2RFVTZ0ZeLys4TD03Xj80aUpIW0lcTU5PSltcXV5fVWZnaGlqa2xtbm9ic3R1dnd4eXp7fH/9oADAMBAAIRAxEAPwD1VJJJJSkkkklKSSSSUpJJU8jqVNUtZ+kf4DgfFySm4q9udjVaOfJ/dbqVhZvWiZD7J/4Ovj+0s5+fa/6EMHlqUlPR29Yj+bZA8XH+AVS7\
rNg5t2+TQsUPcXBziT8VO0Sz4JKbdvWoOrrHT5x/FVX9daHR6Tj8XKpcOFVtB38dklOh/wA4mgx6Dvk7/Yj1/WOueLWfAz/Fc84HcdO6m0apKeqp+sTCdL3DyeFfo63vHDbB4tOv8VxbUauRqND4hJT3VXUsazQksPg7/wAkrQIIkGQe4XBM6jlVGN29o7O1/FX8PrrWn6R\
od56sKSnr0lnY3V2PAFwAnh7dWlaDXNc0OaQQeCElLpJJJKUkkkkpSSSSSlJJJJKf/9D1VJJJJSkkkklKQ7r6qGb7HQO3ifgh5mZXisk+55+izxXI9Z6+W2OY0izI4/ksSU6nVOuBrfe702H6NY+k74rnsjqd952j9HWfzRz/AGnLN9Z9zi+xxdYeSe6VuTTj0uuyHiutn0\
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'''
yellow_light_small = tools.image_resize_image(yellow_light, size=(64, 64))
yellow_light_medium = tools.image_resize_image(yellow_light, size=(128,128))
yellow_light_normal = tools.image_resize_image(yellow_light, size=(256,256))
yellow = dict(image=yellow_light_normal, image_medium=yellow_light_medium, image_small=yellow_light_small)

# green light
green_light = '''\
/9j/4AAQSkZJRgABAgEASABIAAD/7gAOQWRvYmUAZIAAAAAB/9sAhAAMCAgICQgMCQkMEQsKCxEVDwwMDxUYExMVExMYEQwMDAwMDBEMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMAQ0LCw0ODRAODhAUDg4OFBQODg4OFBEMDAwMDBERDAwMDAwMEQwMDAwMDAwMDAw\
MDAwMDAwMDAwMDAwMDAwMDAz/wAARCADhAOEDASIAAhEBAxEB/90ABAAP/8QBPwAAAQUBAQEBAQEAAAAAAAAAAwABAgQFBgcICQoLAQABBQEBAQEBAQAAAAAAAAABAAIDBAUGBwgJCgsQAAEEAQMCBAIFBwYIBQMMMwEAAhEDBCESMQVBUWETInGBMgYUkaGxQiMkFVLBYj\
M0coLRQwclklPw4fFjczUWorKDJkSTVGRFwqN0NhfSVeJl8rOEw9N14/NGJ5SkhbSVxNTk9KW1xdXl9VZmdoaWprbG1ub2N0dXZ3eHl6e3x9fn9xEAAgIBAgQEAwQFBgcHBgU1AQACEQMhMRIEQVFhcSITBTKBkRShsUIjwVLR8DMkYuFygpJDUxVjczTxJQYWorKDByY1w\
tJEk1SjF2RFVTZ0ZeLys4TD03Xj80aUpIW0lcTU5PSltcXV5fVWZnaGlqa2xtbm9ic3R1dnd4eXp7fH/9oADAMBAAIRAxEAPwD1VJJJJSkkkklKSSSSUpJJVsjPookE7n/uN/ikpsoduRTT/OPDfLv9yxMzrTxIc/0x+4z6Sy7OovcfYIn852pSU9JZ1akfzbS7zOgVW3rT\
x3ZX+JWH61jnDc4mfuTWj2g+BSU6dnXYOt7v7I/2Ku76xMBg2WmPD/esq7kFVbPplJTtj6z1T9O4f6/1kev6y1E6XvH9Zv8AsK5P875orOUlPZ09fDtBbXZ5HQ/wVyvq9Z/nGEebdQuEaFYottrEseW/ApKe9qyse76DwT4HQ/ijLha+rXNMWNDwO40K1cHrsw1lk/8AB2c\
/2UlPSpKpj9Souhrv0b/A8fJytpKUkkkkpSSSSSlJJJJKUkkkkp//0PVUkkklKSSSSUpQstrqYX2ODWjuVDKyqsavc/Un6LRySuU6z1/Y4hxD7vzah9Fnm9JTqdR62GtMO9GrgH853wXO5HV7bSWVfo2Hv+cf/IrMfk25LvUtcXP/ACf1UjaxjDZY4MawS5zjAA8SSkpt1u\
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'''
green_light_small = tools.image_resize_image(green_light, size=(64, 64))
green_light_medium = tools.image_resize_image(green_light, size=(128,128))
green_light_normal = tools.image_resize_image(green_light, size=(256,256))
green = dict(image=green_light_normal, image_medium=green_light_medium, image_small=green_light_small)
