import Crypto.Random.random
from Point import Point
from functions import invmod
from pygost import gost34112012256, gost34112012512


# Класс для построения и проверки ЭЦП
# на основе ГОСТ 34.10 - 2018
class GOST_34_10_2018(object):

    def __init__(self, p, a, b, m, q, P):
        # Модуль эллиптической кривой
        self.p = p
        # Коэффициент a эллиптической кривой
        self.a = a
        # Коэффициент b эллиптической кривой
        self.b = b
        # Порядок группы точек эллиптической кривой
        self.m = m
        # Порядок циклической подгруппы точек эллиптической кривой
        self.q = q
        # Базовая точка, которая является генератором
        # циклической подгруппы эллиптической кривой
        self.P = P

# Алгоритм сложения точек
    def add_points(self, point1, point2):

        if point1.isNull():
            return point2
        elif point2.isNull():
            return point1

        x1 = point1.x
        y1 = point1.y
        x2 = point2.x
        y2 = point2.y

        if not (x1 == x2 and y1 == y2):
            try:
                lam = ((y2 - y1) * invmod((x2 - x1) % self.p, self.p)) % self.p
            except:
                return Point(None, None)
        else:
            try:
                lam = ((3 * x1 * x1 + self.a) * invmod(2 * y1, self.p)) % self.p
            except:
                return Point(None, None)

        x3 = (lam ** 2 - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        point3 = Point(x3, y3)
        return point3

# Алгоритм скалярного умножения точки
# Алгоритм удвоения-сложения
    def scalar_multiplication(self, point, n):
        point_template = point
        result_point = Point(None, None)
        while n:
            # побитовое 'и' между последним битом текущего n и 1
            if n & 1:
                result_point = self.add_points(result_point, point_template)
            point_template = self.add_points(point_template, point_template)
            n >>= 1
        return result_point

# Алгоритм генерации открытого и закрытого ключей
    def generation_key(self):
        d = Crypto.Random.random.randint(1, self.q-1)
        Q = self.scalar_multiplication(self.P, d)
        return d, Q

# Алгоритм формирования электронной подписи 256 бит
    def sign_256(self, d, M):

        # Получаем хэш-код сообщения длиной 256 бит
        h = gost34112012256.new(M.encode('UTF-8')).digest()

        # Перевод из массива байтов в целое число
        alpha = int.from_bytes(h, byteorder='big')
        # Высчитываем e
        e = alpha % self.q

        # Если e равно нулю, то положить его 1
        if e == 0:
            e = 1

        # Пока r или s равны нулю
        while True:

            # Генерация k, где оно 0 < k < q
            k = Crypto.Random.random.randint(1, self.q - 1)

            # Расчет точки C
            C = self.scalar_multiplication(self.P, k)

            # Расчет r
            r = C.x % self.q

            # Если r равно нулю, то выполнить цикл заново
            if r == 0:
                continue

            # Расчет s
            s = (r * d + k * e) % self.q

            # Если s равно нулю, то выполнить цикл заново
            if s == 0:
                continue

            # Если s или r неравны нулю, то выйти из цикла
            break

        # Двоичный вектор r
        bit_vector_r = bin(r)[2:].rjust(256, '0')
        # Двоичный вектор s
        bit_vector_s = bin(s)[2:].rjust(256, '0')

        # Цифровая подпись ζ, как конкатенация двух двоичных векторов r и s
        dzeta = bit_vector_r + bit_vector_s

        return dzeta

    # Алгоритм проверки электронной подписи 256 бит
    def verify_256(self, Q, dzeta, M):

        # Получение r и s из цифровой подписи ζ
        r = int(dzeta[0:256], 2)
        s = int(dzeta[257:512], 2)

        # Проверка условий
        if r < 0 or r > self.q or s < 0 or s > self.q:
            return print('Подпись неверна!')

        # Получаем хэш-код сообщения длиной 256 бит
        h = gost34112012256.new(M.encode('UTF-8')).digest()

        # Перевод из массива байтов в целое число
        alpha = int.from_bytes(h, byteorder='big')

        # Вычисляем e
        e = alpha % self.q

        # Если e равно нулю, то положить его 1
        if e == 0:
            e = 1

        # Вычисляем v
        v = invmod(e, self.q)

        # Вычисляем z1 и z2
        z1 = (s * v) % self.q
        z2 = (-r * v) % self.q

        # Вычисляем точку C
        C = self.add_points(self.scalar_multiplication(self.P, z1), self.scalar_multiplication(Q, z2))

        # Определяем R
        R = C.x % self.q

        # Проверка условий верности подписи
        if r == R:
            return print('Подпись верна!')
        else:
            return print('Подпись неверна!')

# # Алгоритм формирования электронной подписи 256 бит
#     def sign_256(self, d, M):
#
#         h = gost34112012256.new(M.encode('UTF-8')).digest()
#         alpha = int.from_bytes(h, byteorder='big')
#         e = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
#         # e = alpha % self.q
#         if e == 0:
#             e = 1
#         print('α(хэш-код сообщения) = ', format(alpha, 'X'), sep='')
#         print('e = ', format(e, 'X'), sep='')
#
#         while True:
#
#             k = 0x77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3
#             # k = Crypto.Random.random.randint(1, self.q - 1)
#
#             C = self.scalar_multiplication(self.P, k)
#             print('Точка C: ')
#             print('x(C) = ', format(C.x, 'X'), sep='')
#             print('y(C) = ', format(C.y, 'X'), sep='')
#
#             r = C.x % self.q
#
#             if r == 0:
#                 continue
#
#             s = (r * d + k * e) % self.q
#
#             if s == 0:
#                 continue
#
#             break
#
#         print('k = ', format(k, 'X'), sep='')
#         print('r = ', format(r, 'X'), sep='')
#         print('s = ', format(s, 'X'), sep='')
#
#         bit_vector_r = bin(r)[2:].rjust(256, '0')
#         bit_vector_s = bin(s)[2:].rjust(256, '0')
#
#         print('Двоичный вектор r = ', bit_vector_r, sep='')
#         print('Двоичный вектор s = ', bit_vector_s, sep='')
#
#         dzeta = bit_vector_r + bit_vector_s
#
#         print('Цифровая подпись = ', dzeta, sep='')
#
#         return dzeta
#
# # Алгоритм проверки электронной подписи 256 бит
#     def verify_256(self, Q, dzeta, M):
#
#         print('Цифровая подпись = ', dzeta, sep='')
#         print('Двоичный вектор r = ', dzeta[0:256], sep='')
#         print('Двоичный вектор s = ', dzeta[257:512], sep='')
#
#         r = int(dzeta[0:256], 2)
#         s = int(dzeta[257:512], 2)
#
#         print('r = ', format(r, 'X'), sep='')
#         print('s = ', format(s, 'X'), sep='')
#
#         if r < 0 or r > self.q or s < 0 or s > self.q:
#             return print('Подпись неверна!')
#
#         h = gost34112012256.new(M.encode('UTF-8')).digest()
#         alpha = int.from_bytes(h, byteorder='big')
#         # e = alpha % self.q
#         e = 0x2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
#         if e == 0:
#             e = 1
#
#         print('α(хэш-код сообщения) = ', format(alpha, 'X'), sep='')
#         print('e = ', format(e, 'X'), sep='')
#
#         v = invmod(e, self.q)
#         print('v = ', format(v, 'X'), sep='')
#
#         z1 = (s * v) % self.q
#         z2 = (-r * v) % self.q
#         print('z1 = ', format(z1, 'X'), sep='')
#         print('z2 = ', format(z2, 'X'), sep='')
#
#         C = self.add_points(self.scalar_multiplication(self.P, z1), self.scalar_multiplication(Q, z2))
#         print('Точка C: ')
#         print('x(C) = ', format(C.x, 'X'), sep='')
#         print('y(C) = ', format(C.y, 'X'), sep='')
#         R = C.x % self.q
#         print('R = ', format(R, 'X'), sep='')
#
#         if r == R:
#             return print('Подпись верна!')
#         else:
#             return print('Подпись неверна!')

    def sign_512(self, d, M):

        h = gost34112012512.new(M.encode('UTF-8')).digest()
        alpha = int.from_bytes(h, byteorder='big')

        e = alpha % self.q

        if e == 0:
            e = 1

        while True:

            k = Crypto.Random.random.randint(1, self.q - 1)

            C = self.scalar_multiplication(self.P, k)

            r = C.x % self.q

            if r == 0:
                continue

            s = (r * d + k * e) % self.q

            if s == 0:
                continue

            break

        bit_vector_r = bin(r)[2:].rjust(512, '0')
        bit_vector_s = bin(s)[2:].rjust(512, '0')

        dzeta = bit_vector_r + bit_vector_s

        return dzeta

    def verify_512(self, Q, dzeta, M):

        r = int(dzeta[0:512], 2)
        s = int(dzeta[513:1024], 2)

        if r < 0 or r > self.q or s < 0 or s > self.q:
            return print('Подпись неверна!')

        h = gost34112012512.new(M.encode('UTF-8')).digest()

        alpha = int.from_bytes(h, byteorder='big')
        e = alpha % self.q

        if e == 0:
            e = 1

        v = invmod(e, self.q)

        z1 = (s * v) % self.q
        z2 = (-r * v) % self.q

        C = self.add_points(self.scalar_multiplication(self.P, z1), self.scalar_multiplication(Q, z2))
        R = C.x % self.q

        if r == R:
            return print('Подпись верна!')
        else:
            return print('Подпись неверна!')
