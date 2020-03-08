$(document).ready(function () {

	/* Password text visibility toogle button click */
	$('.form-group_view-password-button').click(function () {
		var el = $(this).parents('.form-group_password-input').find('input');
		if (el.attr('type') === 'password') {
			el.attr('type', 'text');
			$(this).addClass('active');
		} else {
			el.attr('type', 'password');
			$(this).removeClass('active');
		}
	});
});