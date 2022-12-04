#include <system_error>

namespace stunpp
{
	class stun_validation_error_category_type : public std::error_category
	{
	public:
		const char* name() const noexcept override { return "stun_validation"; }
		std::string message(int) const noexcept override { return "stun_validation"; }
		bool equivalent(const std::error_code& error, int condition) const noexcept override;

	};

	inline const stun_validation_error_category_type& stun_validation_error_category()
	{
		static stun_validation_error_category_type instance;
		return instance;
	}

	enum class stun_validation_error : int32_t
	{
		valid,
		not_stun_message,
		size_mismatch,
		fingerprint_failed,
		username_attribute_not_found,
		realm_attribute_not_found,
		integrity_attribute_not_found,
		integrity_check_failed,
		invalid
	};

	inline std::error_code make_error_code(stun_validation_error error)
	{
		return std::error_code(static_cast<int>(error), stun_validation_error_category());
	}
}

namespace std
{
	template <> struct is_error_code_enum<stunpp::stun_validation_error> : public true_type {};
}