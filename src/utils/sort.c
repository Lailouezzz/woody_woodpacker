// ---
// Includes
// ---

#include <stddef.h>
#include <string.h>

// ---
// Static function definitions
// ---

static void	_swap(char *a, char *b, size_t size)
{
	char	tmp[size];

	memcpy(tmp, a, size);
	memcpy(a, b, size);
	memcpy(b, tmp, size);
}

static int	_quicksort_part(char *tab, size_t size, size_t len, size_t pivot, int(*cmp)(const void*, const void*))
{
	size_t	k;
	size_t	p;

	_swap(&tab[pivot * size], &tab[(len - 1) * size], size);
	pivot = len - 1;
	k = 0;
	p = 0;
	while (k < len)
	{
		if (cmp(&tab[k * size], &tab[pivot * size]) > 0)
		{
			_swap(&tab[k * size], &tab[p * size], size);
			++p;
		}
		++k;
	}
	_swap(&tab[pivot * size], &tab[p * size], size);
	return (p);
}

// ---
// Extern function definitions
// ---

void	quicksort(void *tab, size_t size, size_t len, int(*cmp)(const void*, const void*))
{
	int	pivot;

	if (len != 0)
	{
		pivot = _quicksort_part(tab, size, len, len - 1, cmp);
		quicksort(tab, size, pivot, cmp);
		quicksort((char *)tab + (pivot + 1) * size, size, len - pivot - 1, cmp);
	}
}
