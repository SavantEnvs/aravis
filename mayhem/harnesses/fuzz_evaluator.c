/* Fuzz the GenICam formula evaluator (arvevaluator.c: tokenizer, shunting-yard parser, RPN
 * evaluation) through its public API: the input is a SwissKnife/Converter formula string. */
#include <arv.h>
#include <stdint.h>
#include <string.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	ArvEvaluator *evaluator;
	GError *error = NULL;
	char *expression;

	expression = g_strndup ((const char *) data, size);

	evaluator = arv_evaluator_new (NULL);
	/* Variables, a sub-expression and a constant, as GenICam SwissKnife nodes define them. */
	arv_evaluator_set_int64_variable (evaluator, "A", 3);
	arv_evaluator_set_int64_variable (evaluator, "B", -7);
	arv_evaluator_set_double_variable (evaluator, "X", 2.5);
	arv_evaluator_set_sub_expression (evaluator, "SUB", "A*B+X");
	arv_evaluator_set_constant (evaluator, "K", "42");
	arv_evaluator_set_expression (evaluator, expression);

	(void) arv_evaluator_evaluate_as_double (evaluator, &error);
	g_clear_error (&error);
	(void) arv_evaluator_evaluate_as_int64 (evaluator, &error);
	g_clear_error (&error);

	g_object_unref (evaluator);
	g_free (expression);
	return 0;
}
